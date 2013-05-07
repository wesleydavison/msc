#--- medidas de tendência central e de dispersão ---#
basic_info <- function(METRIC){
#media, mediana, desvio padrão, variância e erro_padrão para a média
    return(list(mean=mean(METRIC),median=median(METRIC),sd=sd(METRIC),var=var(METRIC),err_pad=(sd(METRIC)/sqrt(length(METRIC))))) 
}

#--- Intervalo de Confiança (t-student) --- #
confidence_interval <- function(METRIC, alfa_value=0.05){
	n <- length(METRIC) # Tamanho da amostra
	gl <- n-1     # Graus de liberdade
	alfa <- alfa_value #pode ser 0.05
	t <- qt(1-alfa/2, gl) # Valor de t para a = 0.05 e usando t-student
	sinal <- c(-1,+1) # Sinal mais ou menos
	return (mean(METRIC)+sinal*(t*sd(METRIC)/sqrt(n)))
}

#--- gráficos ---#
histogram <- function(METRIC,name, BREAKER="Sturges"){
	#histograma
	filename <- paste("histogram_",name,".png",sep="")
	mainname <- paste("Histograma de ",name,sep="")
	png(file=filename, bg = "white")
	hist(METRIC, col="white", main=mainname, ylab="Frequencia", xlab=mainname, breaks=BREAKER)
	dev.off()
}
	
box_plot <- function(METRIC,name, BREAKER="Sturges"){
	filename <- paste("boxplot_",name,".png",sep="")
	mainname <- paste("BoxPlot de  ",name,sep="")
	png(file=filename,  bg = "white")
	boxplot(METRIC, main=mainname, ylab=name)
    dev.off()
}

e_cdf <- function(METRIC,name, BREAKER="Sturges"){
	filename <- paste("ecdf_",name,".png",sep="")
	mainname <- paste("ECDF de  ",name,sep="")
	png(file=filename,  bg = "white")
	plot(ecdf(METRIC), main=mainname,verticals= TRUE, do.points = FALSE, xlab="value", ylab="Probabilidade Acumulada")
	dev.off()
}

#--------------- RUN,RUN,RUN !!!-------------------------"
data <- read.table("L7-0.35-aut-5-enc-5.dat", header = TRUE, row.names = 1, sep = "\t", strip.white = TRUE)

cpu_clk <- c(data[[1]])
inst_ret <- c(data[[2]])
l1_miss <- c(data[[4]])

info_cpuclk <- basic_info(cpu_clk)
int_cpuclk <- confidence_interval(cpu_clk)
histogram(cpu_clk,"CPU_CLK")
box_plot(cpu_clk,"CPU_CLK")
e_cdf(cpu_clk,"CPU_CLK")

info_instret <- basic_info(inst_ret)
int_instret <- confidence_interval(inst_ret)
histogram(inst_ret,"INST_RET")
box_plot(inst_ret,"INST_RET")
e_cdf(inst_ret,"INST_RET")
