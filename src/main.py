import sys
import os

# src klasörünü Python'ın arama yoluna ekliyoruz
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == "__main__":
    main()
