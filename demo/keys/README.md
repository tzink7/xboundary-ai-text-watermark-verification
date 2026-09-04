# Demo signing keys

Feature (a) of the demo — "watermark pasted text" — signs with the keys in this
directory. **Use dedicated, throwaway keys here. Never your production keys.**
Anyone who can reach the demo can sign arbitrary text as the domains these keys
belong to.

## Add a key

Name each file exactly `<selector>._watermark-text.<domain>.private.pem`, the
same convention `watermark_dns_tool.py --keygen` uses:

```
cd ../../tools
python3 watermark_dns_tool.py --keygen --domain demo.example --selector 1
mv 1._watermark-text.demo.example.private.pem ../demo/keys/
python3 watermark_dns_tool.py --make-record --selector 1 --domain demo.example \
    --algorithm tzsataitw-1 --pubkey 1._watermark-text.demo.example.public.pem \
    --c sign --nb now --na ongoing --r 1
```

Then publish that TXT record at `1._watermark-text.demo.example` so verification
(feature b) can look the key up.

The server only reads `*.private.pem` files whose name matches the pattern; the
public half is derived on the fly. `*.pem` here is git-ignored.
