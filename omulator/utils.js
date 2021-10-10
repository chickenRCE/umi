var hex = (n) => { return "0x" + n.toString(16) }
var lohi = (lo, hi) => { return hi * 0x100000000 + ((lo+0x100000000)%0x100000000) }
var chr = (c) => { return String.fromCharCode(c) }
var ord = (s) => { return s.charCodeAt(0) }
var u8 = (s) => { return s[0] }
var u16 = (s) => { return s[0] + (s[1] << 8) }
var u32 = (s) => { return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24) }
var u64 = (s) => { return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24)
                            + (s[4] << 32) + (s[5] << 40) + (s[6] << 48) + (s[7] << 56) }
var p8 = (n) => { return [chr(n)] }
var p16 = (n) => { return [n & 0xff, (n >> 8) & 0xff] }
var p32 = (n) => { return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff] }
var p64 = (n) => { return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff,
                            (n >> 32) & 0xff, (n >> 40) & 0xff, (n >> 48) & 0xff, (n >> 56) & 0xff] }


var FileUtils = {
    str2ab: (str) => {
        var buf = new ArrayBuffer(str.length)
        var buf_uint8 = new Uint8Array(buf)
        for (var i = 0; i < str.length; i++) {
            buf_uint8[i] = str.charCodeAt(i)
        }
        return buf_uint8
    },
    get_file: (file) => {
        var file_data;
        $.ajax({
            url: file,
            success: function (data) {
                file_data = data
            },
            async: false,
            mimeType: "text/plain; charset=x-user-defined"
        });
        return FileUtils.str2ab(file_data)
    }
}