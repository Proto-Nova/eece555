################################################################
#
# @author	Jon Hourany
# @date		09/09/13	
# @file		makefile
#
################################################################
all: calc_client calc_server

calc_client: calc_client.c
	gcc calc_client.c -Wall -o calc_client

calc_server: calc_server.c
	gcc calc_server.c -lm -lpthread -Wall -o calc_server
