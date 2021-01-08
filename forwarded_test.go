package forwarded

import (
	"net/http"
	"testing"
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
