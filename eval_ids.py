from scapy import *
import argparse

# Compare the number of packet redirected to IDS to determine false positive

def main(filename_cap, filename_ids):
    cap = rdpcap(filename_cap)
    ids = rdpcap(filename_ids)    
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture', action='store', dest='cap', help='filename of the capture file of the monitored network')
    parser.add_argument('--idscap', action='store', dest='ids', help='filename of the capture file of the ids trafiic')
    args = parser.parser_args()
    main(args.cap, args.ids)
