# tcurl

```
          .--""--.                        .------.
       .-'        '-.                 .-'        '-.
     .'    .----.    '.             .'    .----.    '.
    /     /  ..  \     \           /    .'  curl  '.    \
   |     |  (  )  |     |         |    |   ~~~~~~   |    |
   |      \  ''  /     /           \    '.        .'    /
    \      '----'     /             \     '------'     /
     '.             .'               '.             .'
       '-.______.-'                     '-.______.-'
             \                               /
              '----------- exit ------------'
```

`curl` through Tor. The exit IP stays above the response.

A bare hostname is requested as `https://`. Everything else is passed through to curl.

```bash
tcurl example.com
tcurl -I example.com
tcurl example.com -L -H 'Accept: application/json'
```

The exit address is printed above the response. The check and the fetch share one circuit, so that address is the one that retrieved the page. Green means Tor confirmed it.

A long page opens at the first line in `less`.

| key | action |
|-----|--------|
| space | page down |
| b | page up |
| q | quit |

When the page fits on the screen, it prints and returns to the prompt.

HTML, JSON, and HTTP headers are highlighted. JavaScript and CSS inside a page are colored too.

| option | effect |
|--------|--------|
| `--no-pager`, `--raw` | print the whole response in the terminal |
| `--no-color` | plain text |
| `--color` | color the banner when stdout is piped |
| `-h`, `--help` | help |

Piped output stays plain.

```bash
tcurl example.com | head
```

Needs `tor` on `127.0.0.1:9050`, plus `torsocks` and `curl`. The command is on `PATH` as `/usr/local/bin/tcurl`.
