#TRUSTED 3ac61bac8fc65e170d1427a569dbeff39fb647bd2be7f50bedbd1c3eb547e043766356be356aaf21a4e3c286efc2e3be38d8aac7e6c9e0ec9425659888c3b11df45b5f821b45333160aff7d0d09dc33fadbd13220f50b40f32acd1c9de6339b162020c8303bb2a070cb01b50148e6762a25c13b68f7ed8a1ac8eb49bb00dff485eb5f60f88ca63b4f3703b8a5477b81dab354b6a6fac3980f91aed0a297fbd41d4494f82ba127beb5ff076e364317add9400c760ed117ff9dec1f1a1a259ecad94f45e50b78061305e8f6d56a991ed2e517177fe3737619777260c2da271c6d5c81eabe3d8b49a4214622270d409330b2db3e3a8411a9f93bb412ffb01b4ca25c48881c47c52f22d439073f835af8356966e775cbffa7abebf690e5fd5141b16367454ed1a35e77d13fa6cf28fbec52ab6672072d41f4b3d720dfbb1cf79fce313f2de4d668d7368ad2c2d45a2357b3521c19122d1f81c2910322dfae5c20e0ef35a1d76fb44fd8c70935d6696fbb25374cd735b4c3fb91ac92574dc8ccc7024dcf44fe837bfca0a46747cda784b4217640d302589ae0ab622cda94784c227bc0235d51c41f9d906bc1ac438f9453414563ab9542ebf97d82f3429cab0ae6cf6bbac45889fd21846834afd313ac0eae7aca018e9d8ca336fe660802b11467e426f2cbc6ac5455fb18630f0d05725a397cd45e90bbe63d47bce44403b69f219f6
#
# (C) Tenable Network Security, Inc.
#


if ( ! defined_func("pread") || ! defined_func("fread") ||
     ! defined_func("get_preference") ) exit(0);
if ( ! find_in_path("amap") ) exit(0);


include("compat.inc");


if(description)
{
 script_id(14663);
 script_version ("1.28");
 script_set_attribute(attribute:"plugin_modification_date", value:"2011/03/21");

 script_name(english: "amap (NASL wrapper)");
 script_summary(english: "Performs portscan / RPC scan / application recognition"); 

 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin performs application protocol detection."
 );
 script_set_attribute(
  attribute:"description",
  value:
"This plugin runs amap to find open ports and identify applications on
the remote host. 

See the section 'plugins options' to configure it."
 );
 script_set_attribute(attribute:"see_also", value:"http://www.thc.org/thc-amap/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english: "Port scanners");

 if (NASL_LEVEL >= 3210)
  script_dependencies("portscanners_stub.nasl", "portscanners_settings.nasl");
 else
  script_dependencies("ping_host.nasl", "portscanners_settings.nasl");

 if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "File containing machine readable results : ", value: "", type: "file");

 script_add_preference(name:"Mode", type:"radio", value: "Map applications;Just grab banners;Port scan only");
 script_add_preference(name:"Quicker", type:"checkbox", value: "no");
 script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value: "no");
 script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value: "yes");
 script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value: "yes");

 script_add_preference(name:"Parallel  tasks", type:"entry", value: "");
 script_add_preference(name:"Connection retries", type:"entry", value: "");
 script_add_preference(name:"Connection timeout", type:"entry", value: "");
 script_add_preference(name:"Read timeout", type:"entry", value: "");

 exit(0);
}

#
function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

if (NASL_LEVEL < 2181 || ! defined_func("pread") || ! defined_func("get_preference"))
{
  set_kb_item(name: "/tmp/UnableToRun/14663", value: TRUE);
  display("Script #14663 (amap_wrapper) cannot run - upgrade libnasl\n");
  exit(0);
}

global_var tmpnam;

function do_exit()
{
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++) 
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
  # No result, launch amap
  if (get_kb_item("PortscannersSettings/run_only_if_needed")
      && get_kb_item("Host/full_scan")) exit(0);

tmpdir = get_tmp_dir();
if ( ! tmpdir ) do_exit();
tmpnam = strcat(tmpdir, "/amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediatly with a strange error.
 # I let it run just in case some "harmless" probes are added in a 
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");
 if (! pr) pr = "1-65535";
 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread(cmd: "amap", argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
 }
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

foreach line(split(res))
{
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save 
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
}

if (n_ports != 0)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: 'Host/scanners/amap', value: TRUE);
 if (pr == '1-65535')
   set_kb_item(name: "Host/full_scan", value: TRUE);
}

if (udp_n && n_ports)
  set_kb_item(name: "Host/udp_scanned", value: 1);

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    security_hole(port: port, extra: "Either this port is dynamically allocated or amap killed this service.");

  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   security_note(port: port, proto: proto, extra: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);
 }


do_exit();
