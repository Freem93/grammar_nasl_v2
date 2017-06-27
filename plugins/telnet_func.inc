#TRUSTED 134ca609ed3e9d4198ce4073e24d23da221245c905c2625eb576eec8a82099675c821eb744c6a403ad64be2c0a6715b196b618709085d4c3b2b5d1bf6a590f8326900f1f178a071662100b4f24696f84346b1ecd2fe5268cc8487202c09af51a499042476890294bcc2307f88ccf2ad96e5223ffd53abbc2ceff01dc7d9081ca8e59e19b86d544cf48d0375d7d8023c65ebc15915c27469feec19be039fd4f88026c83ec7c34e35a98ed5e7f862182341a102b325fb4bc0925fc1c6a5099cb0aa3c6d73d7150cbb12181bda1aeacd4eb18b2a60267be2f9c04f9611ac75a051c9d04d741d017441343f7bfb1d6536a13a854280a3b27630e05c418e34bd9967b620422d4d29d02bb15fd7fde5c4e45c72db913874efc8fe785de958514eae5a7ec4b5793ee50178684c301e6408c93107579f6b236fd5b09e5ccd1e68cd7269ef33bbcc2c954c1002d32ad2d6211ab46d8fb6aac4cc2a94c992df5ed93e263d9c4f274c891415a70aedd5394dd9e2dc5641e5971ce286146575181c24f1204dea4b819f57f80132bf3f3b578b85e9cb8a239456d7e5a0f5c1c11548532174a44a17c3fe06bba1d176ffb27cb9797f289c13aeb03853f99bae536c5c9a131d1dc1acb3c8587ee57ef918e709c766b69ff4b4908c5ba77bc3aa5e5007d04198034a4df8431a19cbab02872ea1244ff9801e6889b8e0207a49a47abedaee7da1126
#
# (C) Tenable Network Security, Inc.
#
#
# Revision: 1.23
#

OPT_WILL 	= 0xfb;
OPT_WONT 	= 0xfc;
OPT_DO   	= 0xfd;
OPT_DONT 	= 0xfe;

OPT_SUBOPT 	= 0xfa;
OPT_ENDSUBOPT 	= 0xf0;

function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = string("Services/telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_negotiate(socket:soc);
  close(soc);
  if(strlen(banner))
		replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
  return(banner);
}


function telnet_negotiate(socket, pattern)
{
 local_var opt, code, s, counter, counter2, buf, prev, timeout;

 counter = 0;
 timeout = int(get_preference("checks_read_timeout"));
 if ( timeout <= 0 ) timeout = 5;

 while ( TRUE )
 {
  s   = recv(socket:socket, length:1, timeout:timeout);
  if ( !strlen(s) ) break;
  if ( ord(s[0]) != 0xff) {
	 buf += s;
         if ( pattern && egrep(pattern:pattern, string:buf) ) break;
	 }
  else {
   counter ++;
   s  = recv(socket:socket, length:2);

   if ( ord(s[0]) == OPT_DO ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   else if ( ord(s[0]) == OPT_WILL ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
   else if ( ord(s[0]) == OPT_SUBOPT )
	{
	 # The remote telnet server is autistic :/
	 prev = recv(socket:socket, length:1);
         counter2 = 0;
	 while ( ord(prev) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
	   {
	    prev = s;
 	    # No timeout - the answer is supposed to be cached
	    s    = recv(socket:socket, length:1, timeout:0);
	    if ( ! strlen(s) ) return buf;
	    counter2++;
	    if ( counter2 >= 100 ) return buf;
	   }
	}
  
   # Not necessary and may introduce endless loops
   #if ( ord(s[0]) == OPT_DONT ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   #if ( ord(s[0]) == OPT_WONT ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
  }
  if ( counter >= 100 || strlen(buf) >= 4096 ) break;
 }

 
 return buf;
}

function set_telnet_banner(port, banner)
{
  local_var sb;
  sb = string("Services/telnet/banner/", port);
	replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
}


# (C) Tenable Security

function recv_until(socket, pattern)
{
 local_var r, i, l, buf;
 i = 0; l = 0;

#debug_print('recv_until(pattern=', pattern, ')\n');
 while ( TRUE )
 {
  i ++;
  if ( i > 1024*1024 ) return NULL;
  r = recv(socket:socket, length:1);
  if ( strlen(r) == 0 ) break;
  if (r == '\0') continue;	# The shell sometimes sends back very dirty things
  l ++;
  buf += r;
  # Regex size is limited?
  if (l <= 256)
  {
   if ( egrep(pattern:pattern,string:buf) ) return buf;
  }
  else
  {
   if (egrep(pattern:pattern,string:substr(buf, l - 256))) return buf;
  }
 }
#dump(ddata: buf, dtitle: 'telnet');
#debug_print('recv_until(pattern=', pattern, ') = NULL !\n');
#dump(dtitle: 'telnet', ddata: buf);
 return NULL;
}
