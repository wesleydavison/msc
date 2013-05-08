#this script aims to extract correlations from output traces
#data$ini_sec,data$end_sec,data$ini_mic,data$end_mic,data$src_ip,data$dst_ip,data$src_port,data$dst_port,data$n_bytes,data$n_frames,data$app,data$transp_prot
args<-commandArgs(TRUE)
#listing files
files<-list.files(path = args[1], full.names = TRUE)
#preparing output
cat("file_name,mean_proc,stdev_proc,coef_var_proc,possible_distr,mi_param,k_param2\n", file = "stats.out", append = TRUE, sep = ",")

#iterating over files
for(i in seq(along=files)){
    #print(files[i])
    data=read.csv(files[i], sep=",")

    #mean_iat<-mean(data$inter_arriv_time)
    #stdev_iat<-sd(data$inter_arriv_time)

    mean_proc<-mean(data$process_time)
    stdev_proc<-sd(data$process_time)
    coef_var_proc<-(stdev_proc/mean_proc)

    if(coef_var_proc < 1){
        distr <- "hyper"
    }
    else if(coef_var_proc > 1){
        distr <- "erlang"
        k_param <- ceiling( 1 / (coef_var_proc^2) )
        mi_param <- ( 1 / ((coef_var_proc^2)*k_param*mean_proc) )
    }
    else{
        distr <- "expo"
        mi_param <- ( 1 / mean_proc )
    }

#writing on file
    if(distr == "hyper"){ 
        cat(files[i],mean_proc,stdev_proc,coef_var_proc,distr,0,0, file = "stats.out", append = TRUE, sep = ",")
    }
    else if(distr == "erlang" ){
        cat(files[i],mean_proc,stdev_proc,coef_var_proc,distr,mi_param,k_param,file = "stats.out", append = TRUE, sep = ",")
    }
    else{ #expo
        cat(files[i],mean_proc,stdev_proc,coef_var_proc,distr,mi_param,0, file = "stats.out", append = TRUE, sep = ",")
    }
    cat("\n", file = "stats.out", append = TRUE, sep = "") #gambiarra necessaria
    
#save(cor_size_rate,cor_size_duration,cor_duration_rate, file = "file1.Rdata", ascii = TRUE)
}


