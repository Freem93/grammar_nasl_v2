#TRUSTED 250bd92de57a0509df66a78d7baa6357ab22dadd042c1ec70e172890a3ef774cc5d2dae8104b0a1ceb6ee9a45dff314b3bb6cdf370162dff3b0dd1b130c8c2aea7acda26347fa580950b33c0b5a458666ccbc1ce1d53d68191b6e7d3d1636d6f408f0995a4babf4c83b4975f89176a2496b4a240393b75e1258f3314fdef405efa7a798b38db067db9fb1a42328d4cfbc8ed7eff7ca2d061a0d96287122b802655f2882f55aeae2c9fab435cf58f04f300562f4a766fb3ddbbde58678af0efc14980ad997cad8637906fc9d9925d5cb94a0d8e32702d512a6c07626b63066e67c6c696f80e368aee84c9fe2939bfaccb63e1640a25e4870ea6f5e325778479c6ee514bf5557da13bb3691ed97f9996562574023cd1705ab1a3f724aec8f5613202a1750f547eac76eb9160030d12eea5c1c6443b76db00022404cea153d4fa2a4ecd3e453ec40049aae979962743f4f9e8545d2fd1bb631cffe954c6bc3e07b5dacdb9f394cdabcc32aef7b7a9cc68188598b95a98ccdb85e27219d912dee26556d48f4a05fdccb7fce1b055b8ecf820b6ef5a04e35a322fcaf19982fd9c8148a40c02c4077f287c808ab32a173c7e035fa4faa1d668f6ed3906e656c3c690bd2932a0442a3252fc11e46ca3266b30e2de2ec992ece69b97686df2a737f13a2c76c6ef20ea98ef0b8c23d5bcb76054c46b81992358d588feb552004b71c94767
#
# (C) Tenable Network Security, Inc.
#

# This plugin uses data collected by webmirror.nasl and others.

if ( NASL_LEVEL < 4200 ) exit(0);
include("compat.inc");

if(description)
{
 script_id(46180);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/27");

 script_name(english:"Additional DNS Hostnames");
 script_summary(english:"Reports all found vhosts.");
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus has detected potential virtual hosts.");
 script_set_attribute(attribute:"description", value:
"Hostnames different from the current hostname have been collected by
miscellaneous plugins. Nessus has generated a list of hostnames that
point to the remote host. Note that these are only the alternate
hostnames for vhosts discovered on a web server.

Different web servers may be hosted on name-based virtual hosts.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Virtual_hosting");
 script_set_attribute(attribute:"solution", value:
"If you want to test them, re-scan using the special vhost syntax,
such as :

www.example.com[192.0.32.10]");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("webmirror.nasl", "ssl_cert_CN_mismatch.nasl", "bind_hostname.nasl", "netbios_name_get.nasl");
 script_require_keys("Services/www");
 exit(0);
}

global_var debug_level;

include("misc_func.inc");
include("resolv_func.inc");

global_var	name, seen, tested, report, nb, domain;

function test(h)
{
  h = tolower(h);
  if (h != name && ! seen[h])
  {
    seen[h] = 1; tested ++;
    if (is_same_host(a: h))
    {
      report = strcat(report, '  - ', h, '\n');
      set_kb_item(name:"Host/alt_name", value: h);
      nb ++;
    }
  }

  if (domain && "." >!< h)
  {
    h = h + domain;
    if (h != name && ! seen[h])
    {
      seen[h] = 1; tested ++;
      if (is_same_host(a: h))
      {
        report = strcat(report, '  - ', h, '\n');
        set_kb_item(name:"Host/alt_name", value: h);
        nb ++;
      }
    }
  }
}

www = get_kb_list("Services/www");
if ( isnull(www) ) exit(0, "No web server was found.");

begin = unixtime();

name = get_host_name(); name = tolower(name);
ip = get_host_ip();

report = ""; n = 0;  tested = 0;
seen = make_array(name, 1, ip, 1);

h = rand_str(); tested ++;
if (is_same_host(a: h)) exit(1, "The resolver is broken.");

# Hostnames found by the web crawler.
l = get_kb_list("webmirror/*/hosts");
if (! isnull(l))
  foreach h (make_list(l))
    test(h: h);

# Extract domain name (with a leading dot)
domain = NULL;
if (name != ip)
{
  v = eregmatch(string: name, pattern: "^([^.]+)(\..+\.?)$");
  if (! isnull(v))
  {
    domain = tolower(v[2]);
    h = rand_str(charset:"abcdefghijklmnopqrstuvwxy", length:6); tested ++;
    if (is_same_host(a: h + domain))
    {
      if (debug_level > 0) display("DNS wildcard on domain "+domain);
      domain = NULL;
    }
  }
}

# BIND hostname, SMB name ...
foreach k (make_list("bind/hostname", "SMB/name"))
{
  h = get_kb_item(k);
  if (! isnull(h)) test(h: h);
}

# CN from X509 certificates.
names = make_list();
l = get_kb_list("X509/*/CN");
if (! isnull(l)) names = make_list(names, l);
l = get_kb_list("X509/*/altName");
if (! isnull(l)) names = make_list(names, l);
l = NULL;

foreach h (names) test(h: h);

# Banners from services.
l = get_kb_list("*/banner/*");
if (! isnull(l))
{
  l = make_list(l);
  foreach banner (l)
  {
    if (strlen(banner) > 200) continue;
    foreach line (split(banner, keep: 0))
    {
      while (line != "")
      {
        v = eregmatch(string: line, icase: 1, pattern: "(^|[ :,;@])(([a-z_][a-z0-9_-]*)(\.[a-z_][a-z0-9_-]*)*)(.*)" );
        if (isnull(v)) break;
	test(h: v[2]);
	line = v[5];
      }
    }
  }
  l = NULL;
}

# Brute force.
if (domain)
{
  now = unixtime();
  # Name resolutions take less than 1 s?
  if (now - begin <= tested)
  {
    l = make_list( "smtp", "mta", "pop", "imap", "pop2", "pop3", 
"ads", "backend", "blog", "blogs", "bugs", "careers", 
"cgi", "commumity", "communities", "connect", "corporate", "developer", 
"docs", "download", "downloadcenter", "downloads", "forum", "global", 
"investor", "investors", "jobs", "list", "lists", "mail", "media", "my", 
"news", "press", "public", "remote", "remote-access", "research", "resources",
"search", "services", "shopping", "software", "store", "stores", "support", 
"supportcentral", "video", "videos", "vpn", "vpnaccess", "webmail", "welcome",
"www1", "www2");
    foreach h (l)
    {
      h += domain;
      test(h: h);
    }
    l = NULL;
  }
}

if (nb == 0) exit(0, "No new DNS hostname was found.");
report = 'The following hostnames point to the remote host :\n' + report;
security_note(port:0, extra:report);
if (COMMAND_LINE) display(report, '\n');
