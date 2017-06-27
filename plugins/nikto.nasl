#TRUSTED 48c3c237a09de5575781b4ebceaa2e1345092eb4da8d27ab47042649d8a178579220ebff970a7f97805a21c177f2d8ebdefe44b6b0f7235092db5d0ba26bd24982faa0597284f9c9e9bbfaaa5b59e4c3f7d9932f85a028650d6ef56b7f9208fbb2b12a014cd5b24472bbba96d7a093e3a7ed28a0c3bbc417739649568b0571567b5c87179a4db8b09b428b6213e6ba1fb9f1671c9d68baf94c3fec9f8d74fc749bdbe6fed171d29f85fdeb4164884c1ec3cf9b5e5ce4de2aa6cc5a18a31a33707a41f2e8d677f22e57e9992700ae479ae9bb0a860eb1954db0d06e3b6f8690793b733a79f0eb1e8ae2bb7cdba8740fcab82ff8849cd9c1af9a069762002cd786ff601545946625f84db6d85e61bf3180cbcd2fcf3d047f53df7a7fd93190d2ea53c9825f830be22fc1581fa418d9f032190500ccc6e6878626aed57d9da9809713f524e815f4ad9828743aed0ce743d45ba1f3c28d6305a140c7bf7de25b8326a26930f73a076112edc329cac8cb3a146dc2f5050e3de8f03f26852705c1be28b83ddf9d6f03b6c60798b9ce5bb79424d026ab96de99ce1c2a541b253518bae73f934f8dade7aa59f3bfdc04e89e20edcbac2eaba458120df5095fe61cb6221b2b18f9f90f16ad1d5b9e03a2bbbaaf5db00fe6b1ed5f2d3202cd42a5e52dd00fcc5339af2919666e1c6cf4fdb95ba5aad54c8ee135d83b00b4659623399a8dfc
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL >= 6000) exit(0);

if ( ! defined_func("pread")) exit(0, "nikto.nasl cannot run: pread() is not defined.");
cmd = NULL;

if ( find_in_path("nikto.pl") ) cmd = "nikto.pl";
else if ( find_in_path("nikto") ) cmd = "nikto";

if ( ! cmd && description) {
	if ( NASL_LEVEL < 3000 ) exit(0);
	exit(0, "Nikto was not found in '$PATH'.");
}

include("compat.inc");

if(description)
{
 script_id(14260);
 script_version ("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/09"); 

 script_name(english: "Nikto (NASL wrapper)");
 script_summary(english: "Run Nikto2.");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin runs Nikto2." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Nikto2, an open source (GPL) web server scanner used
to perform comprehensive tests for multiple issues, such as outdated
server versions, potentially dangerous files or programs, version
specific problems, various configuration items, etc.

See the section 'plugins options' to configure it.");
 script_set_attribute(attribute:"see_also", value:"http://www.cirt.net/nikto2" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "httpver.nasl", "logins.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 script_timeout(0);
 script_add_preference(name:"Enable Nikto", type:"checkbox", value:"no");
 script_add_preference(name:"Disable if server never replies 404", type:"checkbox", value:"yes");

 script_add_preference(name:"Root directory", type:"entry", value:"");
 script_add_preference(name:"Pause between tests (s)", type:"entry", value:"");
 script_add_preference(name:"Scan CGI directories",
                       type:"radio", value:"User supplied;All;None");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 1 Show redirects");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 2 Show cookies received");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 3 Show all 200/OK responses");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 4 Show URLs which require authentication");
 script_add_preference(type: "checkbox", value: "no", name: "Display: V Verbose Output");

 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 1 Interesting File / Seen in logs");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 2 Misconfiguration / Default File");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 3 Information Disclosure");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 4 Injection (XSS/Script/HTML)");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 5 Remote File Retrieval - Inside Web Root");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 6 Denial of Service");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 7 Remote File Retrieval - Server Wide");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 8 Command Execution / Remote Shell");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 9 SQL Injection");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 0 File Upload");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: a Authentication Bypass");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: b Software Identification");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: c Remote Source Inclusion");
 if ( NASL_LEVEL >= 3000 )
  script_add_preference(type: "checkbox", value: "no", name: "Tuning: x Reverse Tuning Options (i.e., include all except specified)");

 script_add_preference(type: "checkbox", value: "no", name: "Mutate: 1 Test all files with all root directories");
 script_add_preference(type: "checkbox", value: "no", name: "Mutate: 2 Guess for password file names");
 if ( NASL_LEVEL >= 3000 )
 {
  script_add_preference(type: "checkbox", value: "no", name: "Mutate: 3 Enumerate user names via Apache (/~user type requests)");
  script_add_preference(type: "checkbox", value: "no", name: "Mutate: 4 Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)");
 }

 exit(0);
}

#

function my_cgi_dirs()	# Copied from http_func.inc
{
 local_var	kb;
 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb)) kb = make_list("/cgi-bin", "/scripts", "");
 else kb = make_list(kb, "");
}

if (! COMMAND_LINE)
{
 p = script_get_preference("Enable Nikto");
 if ( "yes" >!< p ) exit(0, "Nikto is not enabled (per policy).");
}

if (! defined_func("pread"))
{
  set_kb_item(name: "/tmp/UnableToRun/14254", value: TRUE);
  display("Script #14254 (nikto_wrapper) cannot run\n");
  exit(0, "nikto.nasl cannot run: pread() is not defined.");
}

if (! cmd)
{
  display("Nikto was not found in $PATH\n");
  exit(0, "Nikto was not found in '$PATH'.");
}

user = get_kb_item("http/login");
pass = get_kb_item("http/password");
ids = get_kb_item("Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0, "No open HTTP port.");

# Nikto may generate many false positives if the web server is broken
p = script_get_preference("Disable if server never replies 404");
if ("yes" >< p || "no" >!< p)
{
no404 = get_kb_item("www/no404/" + port);
  if ( no404 ) exit(0, "The web server on port "+port+" does not return 404 codes.");
  s = http_open_socket(port);
  if (! s) exit(1, "TCP connection to port "+port+" failed.");
  r = http_get(port: port, item: '/'+ rand()+'/'+rand()+'.cgi');
  send(socket: s, data: r);
  r = recv_line(socket: s, length: 512);
  http_close_socket(s);
  if (r =~ '^HTTP/[0-9.]+ +(200|40[13])')
   exit(1, "The web server on port "+port+" does not return 404 code on random pages.");
}

i = 0;
argv[i++] = cmd;

p = script_get_preference("Scan CGI directories");
if (p)
if ("User supplied" >!< p)
{
 argv[i++] = "-Cgidirs";
 argv[i++] = tolower(p);
}
else
{
 v = my_cgi_dirs();
 n = 0;
 if (! isnull(v))   n = max_index(v);
 if (n > 0)
 {
  l = "";
  for (j = 0; j < n; j ++)
  {
   l = strcat(l, v[j]);
   if (! match(string: v[j], pattern: "*/")) l = strcat(l, "/");
   l = strcat(l, " ");
  }
  argv[i++] = "-Cgidirs";
  argv[i++] = l;
 }
}

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

display='';
l = make_list("Display: 1 Show redirects", 
	"Display: 2 Show cookies received",
	"Display: 3 Show all 200/OK responses", 
	"Display: 4 Show URLs which require authentication",
	"Display: V Verbose Output");

foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) display = strcat(display, substr(opt, 9, 9));
}

if (display)
{
 argv[i++] = "-Display";
 argv[i++] = display;
}

mutate = '';
l = make_list("Mutate: 1 Test all files with all root directories",
	"Mutate: 2 Guess for password file names",
	"Mutate: 3 Enumerate user names via Apache (/~user type requests)",
	"Mutate: 4 Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)");
foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) mutate = strcat(mutate, substr(opt, 8, 8));
}
if (strlen(mutate) > 0)
{
 argv[i++] = "-mutate";
 argv[i++] = mutate;
}

p = script_get_preference("Pause between tests (s)");
p = int(p);
if (p > 0)
{
 argv[i++] = "-Pause";
 argv[i++] = p;
}

p = script_get_preference("Root directory");
if (strlen(p) > 0)
{
 argv[i++] = "-root";
 argv[i++] = p;
}


l = make_list("Tuning: 1 Interesting File / Seen in logs",
	"Tuning: 2 Misconfiguration / Default File",
	"Tuning: 3 Information Disclosure",
	"Tuning: 4 Injection (XSS/Script/HTML)",
	"Tuning: 5 Remote File Retrieval - Inside Web Root",
	"Tuning: 6 Denial of Service",
	"Tuning: 7 Remote File Retrieval - Server Wide",
	"Tuning: 8 Command Execution / Remote Shell",
	"Tuning: 9 SQL Injection",
	"Tuning: 0 File Upload",
	"Tuning: a Authentication Bypass",
	"Tuning: b Software Identification",
	"Tuning: c Remote Source Inclusion",
	"Tuning: x Reverse Tuning Options (i.e., include all except specified)");
tuning= '';
foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) tuning = strcat(tuning, substr(opt, 8, 8));
}
if (strlen(tuning) > 0)
{
 argv[i++] = "-Tuning";
 argv[i++] = tuning;
}


p = int(get_preference("checks_read_timeout"));
if (p > 0)
{
 argv[i++] = "-timeout";
 argv[i++] = p;
}

argv[i++] = "-host"; argv[i++] = get_host_ip();
argv[i++] = "-port"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

#p = script_get_preference("Force scan all possible CGI directories");
#if ("yes" >< p) argv[i++] = "-allcgi";
p = script_get_preference("Force full (generic) scan");
if ("yes" >< p) argv[i++] = "-generic";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: cmd, argv: argv, cd: 1);
if (! r)
{
 s = '';
 for (i = 0; ! isnull(argv[i]); i ++) s = strcat(s, argv[i], ' ');
 display('Command exited in error: ', s, '\n');
 exit(0, "Command exited with an error.");	# error
}
if ("No HTTP(s) ports found" >< r) exit(0, "Nikto did not find any HTTP ports.");

report = '\nHere is the Nikto report :\n\n';
foreach l (split(r))
{
  #display(j ++, "\n");
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, extra: report);
if (COMMAND_LINE) display(report, '\n');
