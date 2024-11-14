import zstandard as zstd

input_file = 'ny4-xnas-tvitch-a-20230822T133000.pcap.zst'
output_file = 'ny4-xnas-tvitch-a-20230822T133000.pcap'

with open(input_file, 'rb') as ifh, open(output_file, 'wb') as ofh:
    dctx = zstd.ZstdDecompressor()
    dctx.copy_stream(ifh, ofh)
