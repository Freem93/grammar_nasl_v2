#TRUSTED 720f0b7a351dcb7ecc311b46de7c725d169a3c162d754003643a891b7e7bb2e07743de03db330822e441f83010f98b86a27b56073f22f2043488a2913d03e5977fb96b87bdf54c196fce07499262610771734ba1b407b3c86708b3b15f57e0a89b9f35ccc0443e36a5a9af6fc51d54774fc0ed1a65b61dd68533d1adc8c155ab191839316d2afedfa753ffb2a157c369117242084f9f64b8baf978bdb5c0a51c1cee73ba0e8981959500b6263cedd33d6a9f590e7c6658e48f0cdedee19c1a7b220ea4eebc6835224501026c467ecbc7bcae61c1b5eb703d5b4eb2a17b9725ef300b304306fb4cefac8877680fd7529f0e64fdf4d6d04f4d1b866db7bdbc8d743fd9fa0eee1a37f20734d4d09f25dcd2cc1de5c2c80eefd61e848445c6fb9508a51039e10348e2f7525639b6823a8be9153ac604d449a7b6aef0edbab5824403006455a98b779b970ae133ec93c76ffe295ea778d68f58780998b3abc8a171348c977667c8331adfb882d747df244d8b09609e4ff6518f9a9c3e225ed52e2d3d4366df397f84aebce2e798db8a34035d7cacf0f92d533fca3566f4e337222ea9f188a78b771fe5dd84ed23859b3fcc543b958b1a42722417cc53810c7e64297b2fde49ef1ef9b3b099c14a813e37788169edca4224e7f54d47526d57588c32a40e51501f78d5aec552467ba15720c5fd4baeccf969675ef61f2c3a1a3acefee6
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(45410);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/09/30");

 script_name(english:"SSL Certificate commonName Mismatch");
 script_summary(english:"Compare the X509 CN with the host name");

 script_set_attribute(attribute:"synopsis", value:
"The SSL certificate commonName does not match the host name.");
 script_set_attribute(attribute:"description", value:
"This service presents an SSL certificate for which the 'commonName'
(CN) does not match the host name on which the service listens.");
 script_set_attribute(attribute:"solution", value:
"If the machine has several names, make sure that users connect to the
service through the DNS host name that matches the common name in the
certificate.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("resolv_func.inc");
include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

# Compile a list of names for this host from all name services.
host_names = make_list();

addr = get_host_ip();

# NetBIOS Name Service.
name = get_kb_item("SMB/name");
if (name && name != addr)
{
  # Add the short name.
  host_names = make_list(host_names, tolower(name));

  domain = get_kb_item("SMB/domain");
  if (domain)
  {
    name += "." + domain;

    # Add the full name.
    host_names = make_list(host_names, tolower(name));
  }
}

# Domain Name Service.
name = get_host_name();
if (name != addr)
  host_names = make_list(host_names, tolower(name));

host_names = list_uniq(host_names);

# Get a port that uses SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Get the server's certificate.
cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert))
  exit(1, "The certificate associated with port " + port + " cannot be retrieved.");

# Parse the server's certificate.
cert = parse_der_cert(cert:cert);
if (isnull(cert))
  exit(1, "The certificate associated with port " + port + " cannot be parsed.");

# Extract the Common Names from the certificate.
cns = make_list();

tbs = cert["tbsCertificate"];
subject = tbs["subject"];
foreach field (subject)
{
  if (field[0] != "2.5.4.3")
    continue;
  if ( isnull(field[1]) )
    continue;

  cn = field[1];
  cns = make_list(cns, tolower(cn));
  set_kb_item(name:"X509/" + port + "/CN", value:cn);
}

cns = list_uniq(cns);

# Extract the Alternate Names from the certificate.
ans = make_list();

extensions = tbs["extensions"];
foreach ext (extensions)
{
  if (ext["extnID"] != "2.5.29.17")
    continue;

  foreach value (ext["extnValue"])
  {
    name = value["dNSName"];
    if (isnull(name))
      continue;

    set_kb_item(name:"X509/" + port + "/altName", value:name);
    ans = make_list(ans, tolower(name));
  }
}

ans = list_uniq(ans);

# Combine all the names so we can process them in one go.
cert_names = list_uniq(make_list(cns, ans));
if (max_index(cert_names) <= 0)
  exit(0, "No Common Names and no Subject Alternative Names were found in the certificate associated with port " + port + ".");

# We cannot test if we do not know the hostname, unless we're in PCI
# mode where we're expected to produce a report regardless.
if (!get_kb_item("Settings/PCI_DSS") && max_index(host_names) <= 0)
  exit(1, "No host name is available for the remote target.");

# Compare all names found in the certificate against all names and
# addresses of the host.
foreach cert_name (cert_names)
{
  foreach host_name (host_names)
  {
    # Try an exact match of the names.
    if (cert_name == host_name)
    {
      set_kb_item(name:"X509/" + port + "/hostname_match", value:TRUE);
      exit(0, "The certificate associated with port " + port + " matches one of the host's names exactly.");
    }

    i = stridx(cert_name, ".");
    if (i == 1 && cert_name[0] == "*")
    {
      # Try a wildcard match of the names.
      j = stridx(host_name, ".");
      if (j >= 0 && substr(host_name, j) == substr(cert_name, i))
      {
        set_kb_item(name:"X509/" + port + "/hostname_match", value:TRUE);
        exit(0, "The certificate associated with port " + port + " matches one of the host's names with a wildcard.");
      }
    }
    else
    {
      # Try an address-based match of the name.
      if (is_same_host(a:cert_name, fqdn:TRUE))
      {
        set_kb_item(name:"X509/" + port + "/IP_addr_match", value:TRUE);
        exit(0, "The certificate associated with port " + port + " matches the one of the host's addresses exactly.");
      }
    }
  }
}

# If we don't know any names for the host, consider its address as its
# name in the report.
if (max_index(host_names) <= 0)
  host_names = make_list(addr);

# Report our findings.
if (max_index(host_names) > 1)
  s = "s known by Nessus are";
else
  s = " known by Nessus is";

report =
  '\nThe host name' + s + ' :' +
  '\n' +
  '\n  ' + join(sort(host_names), sep:'\n  ') +
  '\n';

if (cns && max_index(cns) > 0)
{
  if (max_index(cns) > 1)
    s = "s in the certificate are";
  else
    s = " in the certificate is";

  report +=
    '\nThe Common Name' + s + ' :' +
    '\n' +
    '\n  ' + join(sort(cns), sep:'\n  ') +
    '\n';
}

if (ans && max_index(ans) > 0)
{
  if (max_index(ans) > 1)
    s = "s in the certificate are";
  else
    s = " in the certificate is";

  report +=
    '\nThe Subject Alternate Name' + s + ' :' +
    '\n' +
    '\n  ' + join(sort(ans), sep:'\n  ') +
    '\n';
}

security_note(port:port, extra:report);
