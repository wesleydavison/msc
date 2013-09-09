#this script aims to extract correlations from output traces
#data$ini_sec,data$end_sec,data$ini_mic,data$end_mic,data$src_ip,data$dst_ip,data$src_port,data$dst_port,data$n_bytes,data$n_frames,data$app,data$transp_prot
args<-commandArgs(TRUE)
out_file<-"listed-distributions.out"
#listing files
#files<-list.files(path = args[1], full.names = TRUE)
files<-list.files(pattern = "\\.stats")
print(args[1])
#preparing output
cat("file_name,mean_proc,stdev_proc,coef_var_proc,possible_distr,est_mean,est_var,mi_param, param2\n", file = out_file, append = TRUE, sep = ",")

#iterating over files
for(i in seq(along=files)){
    print(files[i])
    if (files[i] == out_file || files[i] == "reading.R" || files[i] == "reading.Rout"){
        next
    }   
    data=read.csv(files[i], sep=",")

    est_mean <- 0
    est_var <- 0

    mean_iat<-mean(data$inter_arriv_time)
    stdev_iat<-sd(data$inter_arriv_time)
    #data_no_outliers <- subset(data, data$process_time > median(data$process_time)*3)
    #data_no_outliers <- subset(data, data$process_time > quantile(data$process_time, 0.85))
    #data_no_outliers <- subset(data, data$process_time > 500000)
    #print(length(data_no_outliers$process_time))
    
    mean_proc<-mean(data$process_time)
    stdev_proc<-sd(data$process_time)

    coef_var_proc<-(stdev_proc/mean_proc)

    if(coef_var_proc > 1){
        distr <- "hyper"
        
    }
    else if(coef_var_proc < 1){
        distr <- "erlang"
        k_param <- ceiling( 1 / (coef_var_proc^2) )
        mi_param <- ( 1 / ((coef_var_proc^2)*k_param*mean_proc) )
        
        est_mean <- 1 / mi_param
        est_var <- 1 / (k_param * (mi_param^2))
    }
    else{
        distr <- "expo"
        mi_param <- ( 1 / mean_proc )
        est_mean <- 1 / mi_param
        est_var <- 1 / (mi_param^2)
    }

#writing on file
    if(distr == "hyper"){ 
        cat(files[i],mean_proc,stdev_proc,coef_var_proc,distr,est_mean,est_var,0,0, file = out_file, append = TRUE, sep = ",")

        #histogram 
        png(filename=paste(files[i],"histogram.png",sep="."))
        hist(data$process_time)
        dev.off()

        ## plot the density
        png(filename=paste(files[i],"density.png",sep="."))
        plot(density(data$process_time))
        dev.off() 
    }
    else if(distr == "erlang" ){
        cat(files[i],mean_proc,stdev_proc,coef_var_proc,distr,est_mean,est_var,mi_param,k_param,file = out_file, append = TRUE, sep = ",")
        
        #generating qqplots
        set.seed(3)
        #erlang distribution is a gamma distribution with k as integer
        samples_len <- length(data$process_time)
        x_dist <- rgamma(samples_len,k_param,mi_param)  #(number of samples, k, mi)
        plot(density(x_dist))
     
        # normalize the gamma so it's between 0 & 1
        # .0001 added because having exactly 1 causes fail
        x_norm <- x_dist / ( max( x_dist ) + .0001 )
        
        #histogram 
        png(filename=paste(files[i],"histogram.png",sep="."))
        hist(data$process_time)
        dev.off()

        ## plot the pdfs on top of each other
        png(filename=paste(files[i],"density.png",sep="."))
        plot(density(x_dist))
        lines(density(data$process_time), col="red" )
        dev.off() 

        png(filename=paste(files[i],"qqplot.png",sep="."))
        qqplot(x_dist, data$process_time)
        dev.off() 
     
    }
    else{ #expo
        cat(files[i],mean_proc,stdev_proc,coef_var_proc,distr,est_mean,est_var,mi_param,0, file = out_file, append = TRUE, sep = ",")
    }
    cat("\n", file = out_file, append = TRUE, sep = "") #necessary
    
}


