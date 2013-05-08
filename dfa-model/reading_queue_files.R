#this script aims to extract correlations from output traces
#data$ini_sec,data$end_sec,data$ini_mic,data$end_mic,data$src_ip,data$dst_ip,data$src_port,data$dst_port,data$n_bytes,data$n_frames,data$app,data$transp_prot

#listing files
files<-list.files()
#preparing output
cat("file_name,mean_iat,stdev_iat,mean_proc_time,stdev_proc_time\n", file = "stats.out", append = TRUE, sep = ",")

#iterating over files
for(i in seq(along=files)){
    print(files[i])
    data=read.csv(files[i], sep=",")

    mean_iat<-mean(data$inter_arriv_time)
    stdev_iat<-sd(data$inter_arriv_time)

    mean_proc_time<-mean(data$process_time)
    stdev_proc_time<-sd(data$process_time)

#writing on file
    cat(files[i],mean_iat,stdev_iat,mean_proc_time,stdev_proc_time, file = "stats.out", append = TRUE, sep = ",")
    cat("\n", file = "stats.out", append = TRUE, sep = "") #gambiarra necessaria
    
#save(cor_size_rate,cor_size_duration,cor_duration_rate, file = "file1.Rdata", ascii = TRUE)
}


