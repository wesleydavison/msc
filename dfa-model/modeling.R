data <- read.table("red_stats.txt", header = TRUE,  sep = ",", strip.white = TRUE)

mean(data$IntArrivTime)
mean(data$ProcessingTime)
