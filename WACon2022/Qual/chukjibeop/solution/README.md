# Writeup

GPS baseband signal data streams

1. Download signal 7z zip file and unzip
- password: `WACon{this_is_not_a_flag}`
- unziped file having `bin` extension must be located at solution directory
2. Build `gnss-sdr` and get into docker instance
- `./run.sh`
3. Run to decode GPS signal
- `gnss-sdr --config_file=./solve.conf`
4. Open generated kml file with Google Earth Pro
- Open file having `kml` extension, such as [pvt.dat_220621_152359.kml](pvt.dat_220621_152359.kml)
5. Get flag

![alt text](out.png)