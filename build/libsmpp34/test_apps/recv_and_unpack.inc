
    memset(local_buffer, 0, sizeof(local_buffer));
    /* Read from socket (This is a sample, must be more complex) **********/
    ret = recv(sock_tcp, local_buffer, 4, MSG_PEEK); 
    if( ret != 4 ){ printf("Error in recv(PEEK)\n");return( -1 );};
    memcpy(&tempo, local_buffer, sizeof(uint32_t)); /* get length PDU */
    local_buffer_len = ntohl( tempo );
    ret = recv(sock_tcp, local_buffer, local_buffer_len, 0); 
    if( ret != local_buffer_len ){ 
        printf("Error in recv(%d bytes)\n", local_buffer_len);return( -1 );};
    /* Print Buffer *******************************************************/
    memset(print_buffer, 0, sizeof(print_buffer));
    ret = smpp34_dumpBuf(print_buffer, sizeof(print_buffer), 
                                            local_buffer, local_buffer_len);
    if( ret != 0 ){ printf("Error in smpp34_dumpBuf():%d:\n%s\n",
                           smpp34_errno, smpp34_strerror ); return( -1 ); };
    printf("-----------------------------------------------------------\n");
    printf("RECEIVE BUFFER \n%s\n", print_buffer);
    /* unpack PDU *********************************************************/
    ret = smpp34_unpack2((void*)&res, local_buffer, local_buffer_len);
    if( ret != 0){ printf( "Error in smpp34_unpack():%d:%s\n",
                            smpp34_errno, smpp34_strerror); return( -1 ); };
    /* Print PDU **********************************************************/
    memset(print_buffer, 0, sizeof(print_buffer));
    ret = smpp34_dumpPdu2(print_buffer, sizeof(print_buffer), (void*)&res);
    if( ret != 0){ printf("Error in smpp34_dumpPdu():%d:\n%s\n",
                           smpp34_errno, smpp34_strerror); return( -1 ); };
    printf("RECEIVE PDU \n%s\n", print_buffer);

