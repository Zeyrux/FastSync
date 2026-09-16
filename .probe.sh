B=/workspace/build-ci
D=/workspace/.probe
rm -rf $D && mkdir -p $D/src $D/dst
head -c 200000 /dev/urandom > $D/src/f.bin
$B/server -p 45995 --allow-unauthenticated >$D/srv.log 2>&1 &
SRV=$!; sleep 0.7
for flags in "" "--incremental" "--incremental --delta"; do
  rm -rf $D/dst; mkdir -p $D/dst
  echo "=== fastsync flags='$flags' fresh: %b %c %l %n ==="
  $B/client --source-dir $D/src --dest-dir $D/dst --server-port 45995 --save-to-disk -a $flags --out-format="%b %c %l %n" 2>&1 | grep -v ERROR
done
echo "=== rsync whole-file: ==="
rm -rf $D/rsrc $D/rdst; mkdir -p $D/rsrc $D/rdst; head -c 200000 /dev/urandom > $D/rsrc/f.bin
rsync -a --out-format="%b %c %l %n" $D/rsrc/ $D/rdst/
kill $SRV 2>/dev/null || true
