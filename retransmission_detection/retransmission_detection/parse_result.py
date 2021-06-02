#!/usr/bin/env python3

import argparse
import os
import sys

def main(pcapfile, inputfile, outputfile): 
    pass
    


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", action="store", type=str, dest="pcapfile")
    parser.add_argument("-i", action="store", type=str, dest="inputfile")
    parser.add_argument("-w", action="store", type=str, dest="outputfile")

    args = parser.parse_args()

    main(args.pcapfile, args.inputfile, args.outputfile)
