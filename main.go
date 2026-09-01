package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var recordTypes = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS,
	dns.TypeTXT, dns.TypeSRV, dns.TypeCAA, dns.TypeSOA,
}

var defaultDNSServers = []string{
	"223.5.5.5:53",
	"114.114.114.114:53",
	"1.1.1.1:53",
	"8.8.8.8:53",
}

var queryDNSServers = defaultDNSServers

type dnsServersFlag []string

func (f *dnsServersFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *dnsServersFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		server := strings.TrimSpace(item)
		if server == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(server); err != nil {
			if net.ParseIP(server) == nil {
				return fmt.Errorf("无效的 DNS 服务器地址: %s", server)
			}
			server = net.JoinHostPort(server, "53")
		}
		*f = append(*f, server)
	}
	if len(*f) == 0 {
		return errors.New("至少指定一个 DNS 服务器")
	}
	return nil
}

var typeNames = map[uint16]string{
	dns.TypeA: "A", dns.TypeAAAA: "AAAA", dns.TypeCNAME: "CNAME", dns.TypeMX: "MX",
	dns.TypeNS: "NS", dns.TypeTXT: "TXT", dns.TypeSRV: "SRV", dns.TypeCAA: "CAA",
	dns.TypeSOA: "SOA",
}

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

type Result struct {
	Domain       string   `json:"domain"`
	StartedAt    string   `json:"started_at"`
	Duration     string   `json:"duration"`
	Records      []Record `json:"records"`
	Subdomains   []string `json:"subdomains"`
	ZoneTransfer bool     `json:"zone_transfer"`
	Warnings     []string `json:"warnings,omitempty"`
}

func normalizeDomain(value string) (string, error) {
	d := strings.TrimSpace(strings.ToLower(value))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if d == "" || strings.ContainsAny(d, "/ :") {
		return "", errors.New("域名格式无效")
	}
	if net.ParseIP(d) != nil || !strings.Contains(d, ".") {
		return "", errors.New("请输入主域名，例如 domain.com")
	}
	return d, nil
}

func lookup(ctx context.Context, domain string) Result {
	started := time.Now()
	r := Result{Domain: domain, StartedAt: started.Format(time.RFC3339)}
	var mu sync.Mutex
	var records []Record
	var wg sync.WaitGroup
	for _, typ := range recordTypes {
		typ := typ
		wg.Add(1)
		go func() {
			defer wg.Done()
			values, err := queryType(ctx, domain, typ)
			if err != nil {
				return
			}
			mu.Lock()
			records = append(records, values...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// A successful AXFR is the only authoritative way to enumerate every record.
	if axfrRecords, ok := tryAXFR(ctx, domain); ok {
		r.ZoneTransfer = true
		records = append(records, axfrRecords...)
	} else {
		r.Warnings = append(r.Warnings, "DNS 区域传送（AXFR）未开放，结果仅包含公开查询到的记录和常见子域探测结果。")
	}
	r.Records = uniqueRecords(records)
	r.Subdomains = discoverSubdomains(ctx, domain, &r.Records)
	r.Duration = time.Since(started).Round(time.Millisecond).String()
	return r
}

func queryType(ctx context.Context, domain string, typ uint16) ([]Record, error) {
	response, err := exchangeDNS(ctx, domain, typ)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, answer := range response.Answer {
		header := answer.Header()
		answerType := dns.TypeToString[header.Rrtype]
		if answerType == "" {
			answerType = typeNames[typ]
		}
		out = append(out, Record{
			Name:  strings.TrimSuffix(header.Name, "."),
			Type:  answerType,
			TTL:   header.Ttl,
			Value: strings.TrimSpace(strings.TrimPrefix(answer.String(), header.String())),
		})
	}
	return out, nil
}

func exchangeDNS(ctx context.Context, name string, typ uint16) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 5 * time.Second}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), typ)
	var lastErr error
	for _, server := range queryDNSServers {
		response, _, err := client.ExchangeContext(ctx, message, server)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Rcode == dns.RcodeServerFailure || response.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("DNS 服务器 %s 返回 %s", server, dns.RcodeToString[response.Rcode])
			continue
		}
		return response, nil
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的 DNS 服务器")
	}
	return nil, lastErr
}

func tryAXFR(ctx context.Context, domain string) ([]Record, bool) {
	response, err := exchangeDNS(ctx, domain, dns.TypeNS)
	if err != nil {
		return nil, false
	}
	var nameservers []string
	for _, answer := range response.Answer {
		if server, ok := answer.(*dns.NS); ok {
			nameservers = append(nameservers, server.Ns)
		}
	}
	for _, server := range nameservers {
		transfer := &dns.Transfer{DialTimeout: 8 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 8 * time.Second}
		message := new(dns.Msg)
		message.SetAxfr(domain + ".")
		channel, err := transfer.In(message, net.JoinHostPort(strings.TrimSuffix(server, "."), "53"))
		if err != nil {
			continue
		}
		var records []Record
		for envelope := range channel {
			if envelope.Error != nil {
				records = nil
				break
			}
			for _, answer := range envelope.RR {
				h := answer.Header()
				typ := dns.TypeToString[h.Rrtype]
				if typ == "" {
					typ = fmt.Sprintf("TYPE%d", h.Rrtype)
				}
				s := answer.String()
				prefix := h.String()
				value := strings.TrimSpace(strings.TrimPrefix(s, prefix))
				records = append(records, Record{strings.TrimSuffix(h.Name, "."), typ, h.Ttl, value})
			}
		}
		if len(records) > 0 {
			return records, true
		}
	}
	return nil, false
}

var commonPrefixes = []string{"www", "mail", "smtp", "pop", "imap", "api", "dev", "test", "staging", "admin", "vpn", "ns1", "ns2", "cdn", "static", "blog", "m", "app", "portal", "git"}

func discoverSubdomains(ctx context.Context, domain string, records *[]Record) []string {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, prefix := range commonPrefixes {
		prefix := prefix
		wg.Add(1)
		go func() {
			defer wg.Done()
			host := prefix + "." + domain
			var hostRecords []Record
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
				values, err := queryType(ctx, host, typ)
				if err == nil {
					hostRecords = append(hostRecords, values...)
				}
			}
			if len(hostRecords) == 0 {
				return
			}
			mu.Lock()
			found = append(found, host)
			*records = append(*records, hostRecords...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Strings(found)
	return found
}

func uniqueRecords(input []Record) []Record {
	seen := make(map[string]bool)
	out := make([]Record, 0, len(input))
	for _, item := range input {
		key := item.Name + "|" + item.Type + "|" + item.Value
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func printResult(r Result) {
	fmt.Printf("\nDNS Search: %s\n耗时: %s | 记录数: %d\n", r.Domain, r.Duration, len(r.Records))
	if r.ZoneTransfer {
		fmt.Println("区域传送: 成功（已获得权威区域记录）")
	} else {
		fmt.Println("区域传送: 未开放")
	}
	if len(r.Warnings) > 0 {
		for _, warning := range r.Warnings {
			fmt.Println("提示:", warning)
		}
	}
	for _, record := range r.Records {
		fmt.Printf("%-35s %-6s %-6d %s\n", record.Name, record.Type, record.TTL, record.Value)
	}
	if len(r.Subdomains) > 0 {
		fmt.Println("\n发现的常见子域:")
		for _, subdomain := range r.Subdomains {
			fmt.Println(" -", subdomain)
		}
	}
}

const page = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DNS Search</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:15px system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1100px;margin:48px auto;padding:0 20px}h1{font-size:38px;margin:0 0 8px;color:#7ee787}p{color:#8b949e}.search{display:flex;gap:10px;margin:26px 0}input{flex:1;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:13px;color:#fff;font-size:16px}button{background:#238636;border:0;border-radius:8px;color:#fff;padding:0 22px;font-size:16px;cursor:pointer}button:disabled{opacity:.6}.panel{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:auto}.meta{padding:14px;border-bottom:1px solid #30363d;color:#8b949e}.warn{padding:12px 14px;color:#f2cc60}.empty{padding:24px;color:#8b949e}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:11px 14px;border-bottom:1px solid #21262d}th{color:#7ee787;font-weight:600}code{color:#79c0ff}</style></head><body><main><h1>DNS Search</h1><p>查询主域名公开 DNS 记录，并尝试发现常见子域名。</p><form class="search" onsubmit="search(event)"><input id="domain" placeholder="domain.com" autofocus><button id="submit">查询</button></form><section id="result" class="panel"><div class="empty">输入域名开始查询</div></section></main><script>async function search(e){e.preventDefault();let d=document.getElementById('domain').value.trim(),b=document.getElementById('submit'),p=document.getElementById('result');if(!d)return;b.disabled=true;b.textContent='查询中...';p.innerHTML='<div class="empty">正在查询，请稍候...</div>';try{let r=await fetch('/api/search?domain='+encodeURIComponent(d)),j=await r.json();if(!r.ok)throw Error(j.error||'查询失败');let rows=j.records.map(x=>'<tr><td>'+esc(x.name)+'</td><td>'+esc(x.type)+'</td><td>'+x.ttl+'</td><td><code>'+esc(x.value)+'</code></td></tr>').join('');p.innerHTML='<div class="meta"><b>'+esc(j.domain)+'</b> · '+j.records.length+' 条记录 · '+j.duration+' · AXFR '+(j.zone_transfer?'成功':'未开放')+'</div>'+(j.warnings||[]).map(x=>'<div class="warn">'+esc(x)+'</div>').join('')+'<table><thead><tr><th>名称</th><th>类型</th><th>TTL</th><th>值</th></tr></thead><tbody>'+rows+'</tbody></table>'}catch(x){p.innerHTML='<div class="warn">'+esc(x.message)+'</div>'}finally{b.disabled=false;b.textContent='查询'}}function esc(x){return String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}</script></body></html>`

func runWebUI(addr string) error {
	tmpl := template.Must(template.New("index").Parse(page))
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) { _ = tmpl.Execute(w, nil) })
	http.HandleFunc("/api/search", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		domain, err := normalizeDomain(req.URL.Query().Get("domain"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		result := lookup(req.Context(), domain)
		_ = json.NewEncoder(w).Encode(result)
	})
	log.Printf("Web UI: http://%s", addr)
	return http.ListenAndServe(addr, nil)
}

func main() {
	domainFlag := flag.String("d", "", "要查询的主域名，例如 domain.com")
	webui := flag.Bool("webui", false, "启动 Web UI")
	addr := flag.String("addr", "127.0.0.1:8080", "Web UI 监听地址")
	var dnsFlags dnsServersFlag
	flag.Var(&dnsFlags, "dns", "自定义 DNS 服务器，可重复指定或用逗号分隔（默认使用内置列表）")
	flag.Parse()
	if len(dnsFlags) > 0 {
		queryDNSServers = dnsFlags
	}
	if *webui {
		if err := runWebUI(*addr); err != nil {
			log.Fatal(err)
		}
		return
	}
	domain := *domainFlag
	if domain == "" {
		fmt.Print("请输入要查询的主域名（例如 domain.com）：")
		_, _ = fmt.Scanln(&domain)
	}
	domain, err := normalizeDomain(domain)
	if err != nil {
		log.Fatal(err)
	}
	printResult(lookup(context.Background(), domain))
}
