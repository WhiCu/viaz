awk '
/^import \(/ {
    print
    print "\t\"github.com/whicu/viaz/frame/varint\""
    next
}
{print}
' frame/frame_test.go > frame/frame_test.go.tmp && mv frame/frame_test.go.tmp frame/frame_test.go
