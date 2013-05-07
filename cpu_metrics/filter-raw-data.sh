#!/bin/bash

in_folder=$1
out_folder=$2

for sig_set in L7 SnortWeb;do
    for prob in 0.35 0.55 0.75 0.95;do
        for aut in 1 3 4 5;do
            for enc in 1 2 3 4 5;do
                if [[ ($aut == 1 && $enc != 1) && ($aut == 1 && $enc != 2) && ($aut == 1 && $enc != 3) ]]; then
                    #--- D2FA does not work with this type of encoding
                    continue
                elif [[ $aut == 3 && $enc != 4 ]]; then
                    #--- RawDFA works only works with TableStyle encoding
                    continue
                elif [[ ($aut == 4 && $enc != 1) && ( $aut == 4 && $enc != 2 ) && ( $aut == 4 && $enc != 3 ) ]]; then
                    #--- FastFA does not work with this type of encoding
                    continue
                elif [[ $aut == 5 && $enc != 5 ]]; then 
                    #--- RcDfa works only with ALE encoding 
                    continue
                else
                    output="$sig_set-$prob-aut-$aut-enc-$enc.txt"
                    echo -e "\tCPU_CLK\tINST_RET\tL1_HIT\tL1_MISS" >> $out_folder/$output
                    for rep in {1..10};do
                        file_name="papiLog-$sig_set-$prob-aut-$aut-enc-$enc-rep-$rep.txt"
                        for i in {1..4};do
                            metrics[$i]=$(tail -n 1 $in_folder/$file_name | awk -v it=$i -F' ' '{ print $it }')
                        done
                        echo -e "rep_$rep\t${metrics[1]}\t${metrics[2]}\t${metrics[3]}\t${metrics[4]}" >> $out_folder/$output
                    done
                fi
            done
        done
    done
done
