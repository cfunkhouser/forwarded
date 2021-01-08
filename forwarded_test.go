package forwarded

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestXFFDeterminerBy(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no X-Forwarded-By header": {
			header: http.Header{},
		},
		"single ipv4 entry": {
			header: http.Header{
				"X-Forwarded-By": []string{"1.1.1.1:8080"},
			},
			want: "1.1.1.1:8080",
		},
		"single ipv6 entry": {
			header: http.Header{
				"X-Forwarded-By": []string{"[2606:4700:4700::1111]:8080"},
			},
			want: "[2606:4700:4700::1111]:8080",
		},
		"multiple ipv4 entries": {
			header: http.Header{
				"X-Forwarded-By": []string{"1.1.1.1:8080, 2.2.2.2:9090"},
			},
			want: "1.1.1.1:8080",
		},
		"multiple ipv6 entries": {
			header: http.Header{
				"X-Forwarded-By": []string{"[2606:4700:4700::1111]:8080, [2606:4700:4700::2222]:9090"},
			},
			want: "[2606:4700:4700::1111]:8080",
		},
		"multiple mixed entries": {
			header: http.Header{
				"X-Forwarded-By": []string{"1.1.1.1:8080, [2606:4700:4700::2222]:9090"},
			},
			want: "1.1.1.1:8080",
		},
	} {
		testDeterminer := &xffDeterminer{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.By(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestXFFDeterminerFor(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no X-Forwarded-For header": {
			header: http.Header{},
		},
		"single ipv4 entry": {
			header: http.Header{
				"X-Forwarded-For": []string{"1.1.1.1:8080"},
			},
			want: "1.1.1.1:8080",
		},
		"single ipv6 entry": {
			header: http.Header{
				"X-Forwarded-For": []string{"[2606:4700:4700::1111]:8080"},
			},
			want: "[2606:4700:4700::1111]:8080",
		},
		"multiple ipv4 entries": {
			header: http.Header{
				"X-Forwarded-For": []string{"1.1.1.1:8080, 2.2.2.2:9090"},
			},
			want: "1.1.1.1:8080",
		},
		"multiple ipv6 entries": {
			header: http.Header{
				"X-Forwarded-For": []string{"[2606:4700:4700::1111]:8080, [2606:4700:4700::2222]:9090"},
			},
			want: "[2606:4700:4700::1111]:8080",
		},
		"multiple mixed entries": {
			header: http.Header{
				"X-Forwarded-For": []string{"1.1.1.1:8080, [2606:4700:4700::2222]:9090"},
			},
			want: "1.1.1.1:8080",
		},
	} {
		testDeterminer := &xffDeterminer{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.For(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestXFFDeterminerHost(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no X-Forwarded-Host header": {
			header: http.Header{},
		},
		"hostname": {
			header: http.Header{
				"X-Forwarded-Host": []string{"api.example.com"},
			},
			want: "api.example.com",
		},
		"ipv4 address": {
			header: http.Header{
				"X-Forwarded-Host": []string{"1.1.1.1"},
			},
			want: "1.1.1.1",
		},
		"ipv6 address": {
			header: http.Header{
				"X-Forwarded-Host": []string{"[2606:4700:4700::1111]"},
			},
			want: "[2606:4700:4700::1111]",
		},
		"ipv4 hostport": {
			header: http.Header{
				"X-Forwarded-Host": []string{"1.1.1.1:8080"},
			},
			want: "1.1.1.1:8080",
		},
		"ipv6 hostport": {
			header: http.Header{
				"X-Forwarded-Host": []string{"[2606:4700:4700::1111]:8080"},
			},
			want: "[2606:4700:4700::1111]:8080",
		},
	} {
		testDeterminer := &xffDeterminer{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.Host(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestXFFDeterminerProto(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no X-Forwarded-Proto header": {
			header: http.Header{},
		},
		"known proto": {
			header: http.Header{
				"X-Forwarded-Proto": []string{"http"},
			},
			want: "http",
		},
		"unknown proto": {
			header: http.Header{
				"X-Forwarded-Proto": []string{"nonsense"},
			},
			want: "nonsense",
		},
	} {
		testDeterminer := &xffDeterminer{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.Proto(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestParseForwarded(t *testing.T) {
	for tn, tc := range map[string]struct {
		header http.Header
		want   parsedHeader
	}{
		"zero header": {},
		"no Forwarded header": {
			header: http.Header{},
		},
		"rfc example": {
			header: http.Header{
				"Forwarded": []string{"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"},
			},
			want: parsedHeader{
				fors:  []string{"192.0.2.43", "198.51.100.17"},
				bys:   []string{"203.0.113.60"},
				host:  "example.com",
				proto: "http",
			},
		},
	} {
		t.Run(tn, func(t *testing.T) {
			got := parseForwarded(tc.header)
			if diff := cmp.Diff(got, tc.want, cmp.AllowUnexported(parsedHeader{})); diff != "" {
				t.Errorf("mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestRFC7239DeterminerBy(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no Forwarded header": {
			header: http.Header{},
		},
		"only by segment": {
			header: http.Header{
				"Forwarded": []string{"by=1.1.1.1:8080"},
			},
			want: "1.1.1.1:8080",
		},
		"no by segment": {
			header: http.Header{
				"Forwarded": []string{"for=[2606:4700:4700::1111]:8080"},
			},
		},
		"rfc example": {
			header: http.Header{
				"Forwarded": []string{"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"},
			},
			want: "203.0.113.60",
		},
	} {
		testDeterminer := &rfc7239Determiner{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.By(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestRFC7239DeterminerFor(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no Forwarded header": {
			header: http.Header{},
		},
		"only by segment": {
			header: http.Header{
				"Forwarded": []string{"for=1.1.1.1:8080"},
			},
			want: "1.1.1.1:8080",
		},
		"no for segment": {
			header: http.Header{
				"Forwarded": []string{"by=[2606:4700:4700::1111]:8080"},
			},
		},
		"rfc example": {
			header: http.Header{
				"Forwarded": []string{"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"},
			},
			want: "192.0.2.43",
		},
	} {
		testDeterminer := &rfc7239Determiner{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.For(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestRFC7239DeterminerHost(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no Forwarded header": {
			header: http.Header{},
		},
		"only host segment": {
			header: http.Header{
				"Forwarded": []string{"host=api.example.com"},
			},
			want: "api.example.com",
		},
		"no host segment": {
			header: http.Header{
				"Forwarded": []string{"for=1.2.3.4:4321;by=[2606:4700:4700::1111]:8080"},
			},
		},
		"rfc example": {
			header: http.Header{
				"Forwarded": []string{"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"},
			},
			want: "example.com",
		},
	} {
		testDeterminer := &rfc7239Determiner{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.Host(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}

func TestRFC7239DeterminerProto(t *testing.T) {
	for tn, tc := range map[string]struct {
		want   string
		header http.Header
	}{
		"zero header": {},
		"no Forwarded header": {
			header: http.Header{},
		},
		"only proto segment": {
			header: http.Header{
				"Forwarded": []string{"proto=http"},
			},
			want: "http",
		},
		"no proto segment": {
			header: http.Header{
				"Forwarded": []string{"for=1.2.3.4:4321;by=[2606:4700:4700::1111]:8080"},
			},
		},
		"rfc example": {
			header: http.Header{
				"Forwarded": []string{"for=192.0.2.43,for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com"},
			},
			want: "http",
		},
	} {
		testDeterminer := &rfc7239Determiner{}
		t.Run(tn, func(t *testing.T) {
			if got := testDeterminer.Proto(tc.header); got != tc.want {
				t.Errorf("got: %q want: %q", got, tc.want)
			}
		})
	}
}
