set term wxt persist
set title "Fuzzer Stats"
set xlabel "Fuzz Cases"
set ylabel "Count"
set logscale x
set datafile separator ","
plot "stats.txt" u 1:2 w l
