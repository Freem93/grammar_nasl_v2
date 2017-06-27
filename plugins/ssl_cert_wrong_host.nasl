#TRUSTED a2d9b6cf52f757ccac9e95afd2b23eb0e94c3fa125b781cd5516964f40888a13f96010171976f3ef36477ef8f09f5b3d95829fa9f6e4e242ee1cf6ab9ffdc0b37e439dee9b111bbb036ae746bc08fcdb9dd5984cd52729dd9522ef6092f22bbb247e673419a4a068617f242e661ad9602b4a0f3cd060eb2474f2332c73fa8ff1f696c6bb831365bb68c7faaff71ab83be70338c3e32dda42ff0b5752361a4d35f7d0add8b94bdfc19a6c9f5f69112714aedf0058e3c6e7256dadd0cc3a25f84ebd49398cdbc993ef6b6f9b5ed022786f028d6e4c2367a8b037073df7097033ff385b5bb110af4f4b3540b79c6edc10864b8b12c9d6aa170102323840e9ef81737be37ca35e527b56333ff8494f4581f5b41a009645a19133927f0ae1affb6660461b08257fdb9a132bac11b3a50aa782d103b5d6a9eef400175fe28e8eb5146f56cfb422d69838834f8a992cbabcda874b1a98f2cf050d796139e944623cbbf5990b2f3142798a354f04809159ef63c0d0f2f8c9c6570ceb5e46d27a76326d34ef6d9afb92d5ea1992b8966e3a8c274b092735aea02ef087c6ffd7b4858e5de11e2c9f43a3778655c6325035d2817f555400927476a778a0c1d5a2a2c4ed35e607e3b2547ec0324b93abe71fd67abce1351a4b689508ff297e3a177c3be4be935da62c1efd9dcd28211f08ffd55f77c3f79c38e85780a3466ae13bf9e915630d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(45411);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/03/11");
 
 script_name(english:"SSL Certificate with Wrong Hostname");
 script_summary(english:"Checks that the X509 CN matches the target host");
 
 script_set_attribute(attribute:"synopsis", value:"The SSL certificate for this service is for a different host.");
 script_set_attribute(attribute:"description", value:
"The commonName (CN) of the SSL certificate presented on this service
is for a different machine.");
 script_set_attribute(attribute:"solution", value:"Purchase or generate a proper certificate for this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencies(
   "ssl_supported_versions.nasl",
   "ssl_cert_CN_mismatch.nasl",
   "ifconfig_inet4.nasl",
   "ifconfig_inet6.nasl",
   "netbios_multiple_ip_enum.nasl",
   "wmi_list_interfaces.nbin"
 );
 if (NASL_LEVEL >= 4200)
   script_dependencies("alternate_hostnames.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("resolv_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Check if we know any names for the host.
addr = get_host_ip();
dns_name = get_host_name();
smb_name = get_kb_item("SMB/name");

if ( ! get_kb_item("Settings/PCI_DSS" ))  
{
if (dns_name == addr && (!smb_name || smb_name == addr))
  exit(1, "No host names are known for the remote target.");
}

# Compile a list of all the host's identities.
ids = make_list();

ifs = get_kb_item("Host/SMB/InterfaceList");
if (ifs)
{
  foreach line (split(ifs))
  {
    matches = eregmatch(string:line, pattern:"^ +- +[^=]+= *([^ /]+) */");
    if (!isnull(matches))
      ids = make_list(ids, matches[1]);
  }
}

kbs = make_list(
  "Host/ifconfig/IP4Addrs",
  "Host/ifconfig/IP6Addrs",
  "Host/Netbios/IP",
  "Host/alt_name"
);

foreach kb (kbs)
{
  list = get_kb_list(kb);
  if (!isnull(list))
    ids = make_list(ids, list);
}

for (i = 0; i < max_index(ids); i++)
{
  ids[i] = tolower(ids[i]);
}

ids = list_uniq(ids);

if (!get_kb_item("Settings/PCI_DSS") && max_index(ids) <= 0)
  exit(1, "No identities are known for the remote target.");

# Get a port that uses SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");





# Check if we already have a match between this host and the
# certificate on this port.
if (get_kb_item("X509/" + port + "/hostname_match"))
  exit(0, "The certificate associated with port " + port + " matches the host name.");

# Compile a list of all the Common Names and Alternate Names in the
# certificate.
names = make_list();

cns = get_kb_list("X509/" + port + "/CN");
if (!isnull(cns))
{
  cns = make_list(cns);
  names = make_list(names, cns);
}

ans = get_kb_list("X509/" + port + "/altName");
if (!isnull(ans))
{
  ans = make_list(ans);
  names = make_list(names, ans);
}

for (i = 0; i < max_index(names); i++)
{
  names[i] = tolower(names[i]);
}

names = list_uniq(names);

if (max_index(names) <= 0)
  exit(0, "No Common Names and no Subject Alternative Names were found in the certificate associated with port " + port + ".");

# Compare all names found in the certificate against all the
# identities of the host.
foreach name (names)
{
  if (substr(name, 0, 1) != "*.")
  {
    # Try an exact match of the names.
    if (is_same_host(a:name, fqdn:TRUE))
      exit(0, "The certificate associated with port " + port + " matches one of the host's names exactly.");

    # Try an exact match of the identities.
    foreach id (ids)
    {
      if (is_same_host(a:name, b:id, fqdn:TRUE))
        exit(0, "The certificate associated with port " + port + " matches one of the host's identities exactly.");
    }
  }
  else
  {
    # Try a wildcard match of the identities.
    domain = tolower(substr(name, 1));
    foreach id (ids)
    {
      j = stridx(id, ".");
      if (j >= 0 && tolower(substr(id, j)) == domain)
        exit(0, "The certificate associated with port " + port + " matches one of the host's identities with a wildcard.");
    }
  }
}

# Report our findings.
if (max_index(ids) > 0)
  id_s = "ies known by Nessus are";
else
  id_s = "y known by Nessus is";

report =
  '\nThe identit' + id_s + ' :' +
  '\n' +
  '\n  ' + join(sort(ids), sep:'\n  ') +
  '\n  ' + get_host_name() + 
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

security_warning(port:port, extra:report);
