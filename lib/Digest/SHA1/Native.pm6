unit module Digest::SHA1::Native;

use NativeCall;

# Use SHA1 function from OpenSSL library - libcrypto
sub SHA1(Blob, size_t, CArray[uint8]) is native('crypto') {*}

multi sub sha1-hex(Str $in) is export {
    sha1-hex($in.encode);
}

multi sub sha1-hex(Blob $in) is export {
    sha1($in)>>.fmt("%02x").join.lc;
}

multi sub sha1(Str $in) is export {
    sha1($in.encode);
}

multi sub sha1($in) is export {
    my size_t $len = $in.elems;
    my $hash = CArray[uint8].allocate(20);
    SHA1($in, $len, $hash);
    return $hash;
}
