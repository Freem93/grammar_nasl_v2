#TRUSTED 9496129ec4553de56a4297c35bfe27aa1f08d470e7847a2ad201b35a165275aa646b7da0c0edf912e92e92271c46ac8306bb357e2cddb53f9162dada6ac7cfc1e2cf9e772fc2e552c6acdeacab3d489e7d2932b00f83ff862839cf46db25b7abdbcaed4692e54067145aff359bc83cfab4bf365da70698eb73d93dcaaa9b9c837bffbff1ff805b264cf5b7ab4049b73e81d1883e52c087b3640ed9c01de15ba158e1f6b7224681b38c7de8f121238b31c704d3bd0ea572f2bcb8c183c8c6fc2e6cfc90d313217cb907193aab3c489d71d7a52badefc15810105e6c5f5584ef395cfa28cbd9febd22af1a06fcb454633c9b916ffbfc6a30ad1f137fa93e2013f1541efa6790af1dd16e771218e1ef5d68833d19820e12c2f79de0e42e6fb7f68e832c7166390d6607a65ef9db44da07fc6a2bbf19cdbb956feb13665dffcfdbaca7846769d0ae60ef21e504d8650e551263d79999d0741eeacb1d9da9bb364b92a9b350fa1a19030dda4d90e0febceaa64ec3b9f2850c45734ee03a919e279047683631325916791322a25af495296ea88a26b28e58d97509a406e7711f1367f652351094344cb3986daa2ace60809e394d9d292731bbdf46f56a783d483ef7b22a74655e661a2a54443bcad993b395b812f7e207373336b4622b2a4e7bd5571dedbefe97f8ef2b1753d28d1d91265a42ff65e20d34fe8b6a8e9d77cca3790d16
#%NASL_MIN_LEVEL 5200
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72459);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/02/19");

  script_name(english:"Certificate Revocation List Expiry");
  script_summary(english:"Checks if any CRLs have expired.");

  script_set_attribute(attribute:"synopsis", value:"The Certificate Revocation List has expired.");
  script_set_attribute(attribute:"description", value:
"The X.509 Certificate Revocation List (CRL) has not been updated, and
is currently past its self-reported expiry date.  This indicates that
the CRL may be misconfigured.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc5280");
  script_set_attribute(attribute:"solution", value:
"Check the Certificate Authority's CRL configuration and the system
clock.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_END_REPORT);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  exit(0);
}

include("datetime.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("x509_func.inc");

function parse()
{
  local_var blob, crl, pos, ret, seq, str;

  blob = _FCT_ANON_ARGS[0];
  if (isnull(blob))
    return NULL;

  crl = make_array();

  # Note that this uses sloppy parsing due to the input data almost
  # certainly being truncated.

  # RFC 5280, Section 5.1.1 :: CertificateList Fields
  seq = der_decode(data:blob, sloppy:TRUE);
  if (isnull(seq) || seq[0] != 0x30)
    return NULL;
  blob = NULL;

  # RFC 5280, Section 5.1.2 :: Certificate List "To Be Signed"
  seq = der_decode(data:seq[1], sloppy:TRUE);
  if (isnull(seq) || seq[0] != 0x30)
    return NULL;

  # The body of the inner sequence is what we'll be concentrating on.
  blob = seq[1];
  pos = 0;

  # RFC 5280, Section 5.1.2.1 :: Version
  # Note that this field is optional.
  ret = der_decode(data:blob, pos:pos);
  if (!isnull(ret) && ret[0] == 0x02)
    pos = ret[2];

  # RFC 5280, Section 5.1.2.2 :: Signature
  ret = der_decode(data:blob, pos:pos);
  if (isnull(ret) || ret[0] != 0x30)
    return NULL;
  pos = ret[2];

  # RFC 5280, Section 5.1.2.3 :: Issuer Name
  str = substr(blob, pos);
  if (isnull(str))
    return NULL;

  ret = der_decode(data:str);
  if (ret[0] != 0x30)
    return NULL;

  ret = parse_rdn_sequence(seq:ret[1]);
  if (isnull(ret))
    return NULL;
  crl["issuer"] = ret;

  ret = der_decode(data:blob, pos:pos);
  if (isnull(ret))
    return NULL;
  pos = ret[2];

  # RFC 5280, Section 5.1.2.4 :: This Update
  str = substr(blob, pos);
  if (isnull(str))
    return NULL;

  ret = parse_time(time:str);
  if (isnull(ret))
    return NULL;
  crl["thisUpdate"] = ret;

  ret = der_decode(data:blob, pos:pos);
  if (isnull(ret))
    return NULL;
  pos = ret[2];

  # RFC 5280, Section 5.1.2.5 :: Next Update
  # Note that this field is optional.
  str = substr(blob, pos);
  if (!isnull(str))
  {
    ret = parse_time(time:str);
    if (!isnull(ret))
      crl["nextUpdate"] = ret;
  }

  # We stop parsing at this point because the remainder of the CRL can
  # be on the order of 50+MB and take on the order of 600+MB of RAM to
  # parse.

  return crl;
}

# Note that this entire script is written to be very tolerant, the
# only thing that is treated as a real failure is a parse error, since
# that's a coding error that we need to be alerted to. The reason for
# this is that the CRL extension may contain nonsensical data, and
# we don't want one crazy certificate to mess up this script for the
# entire scan.

# Start by checking if this script is enabled. Due to its category,
# this script will run by the scheduler regardless of the policy, so
# we have to manually adhere to the policy.
if (!is_plugin_enabled(script_family:"General", plugin_id:72459))
  exit(0, "This plugin was not enabled by the policy.");

# This script connects to external hosts, *arbitrary* hosts, pulled
# from an X.509 extension, which anyone that generates a self-signed
# certificate can make point anywhere. So we need to be absolutely
# sure the user wants us to continue.
get_global_kb_item_or_exit("global_settings/enable_crl_checking");

# We've got our parser rigged up to handle truncated DER encoding, and
# all the fields we want are at the start of the CRL, so we'll lower
# the HTTP response body size to 1 KiB.
http_set_max_req_sz(1024);

# Get CRL URLs from global KB.
entries = get_global_kb_list("SSL/CRL/*/*/*/URL");
if (max_index(keys(entries)) == 0)
  exit(0, "No CRL URLs were found in the global KB.");

# Create the structure that will be used to store the parsed CRLs.
crls = make_array();

# Flatten the entries out to get the list of URLs.
urls = list_uniq(make_list(entries));

# Parse each URL and store the result.
foreach url (urls)
{
  # Split the URL into its components.
  fields = split_url(url:url);
  if (isnull(fields))
    continue;

  # Only attempt to connect to URLs that are HTTP(S).
  if (fields["scheme"] !~ "https?")
    continue;

  # Figure out the transport we should be using, choosing TLSv1 as our
  # HTTPS protocol due to its ubiquity.
  if (fields["ssl"])
    transport = ENCAPS_TLSv1;

  # Connect to the host indicated by the URL, setting as many parameters
  # as we can with fields from the URL, to guard against wacky CRL URLs.
  res = http_send_recv3(
    target          : fields["host"],
    port            : fields["port"],
    transport       : transport,

    method          : "GET",
    username        : fields["username"],
    password        : fields["password"],
    item            : fields["page"],

    follow_redirect : 3
  );

  # Check if we got any data in the response.
  if (isnull(res) || !res[2])
    continue;

  # Attempt to parse the potentially truncated CRL.
  crl = parse(res[2]);
  if (isnull(crl))
    continue;

  # We're checking whether the CRL has expired, but the expiry time is
  # an optional field, so check that it exists.
  if (isnull(crl["nextUpdate"]))
    continue;

  # Check whether the CRL has expired, but to avoid timezone madness and
  # clock drift, we only flag CRLs that are at least one day expired.
  # This should reduce false positives and support tickets, and is the
  # same thing we do with X.509 certificates.
  if (date_cmp(crl["nextUpdate"]) < 0)
    continue;

  # Format the report, which will likely be used by several hosts/ports/certs.
  report =
    '\nThe CRL below was found to be past its self-reported expiry date :' +
    '\n' +
    '\n  URL            : ' + url +
    '\n  Issuer         : ' + format_dn(crl["issuer"]) +
    '\n  Subject        : {{SUBJECT}}' +
    '\n  Date of Issue  : ' + crl["thisUpdate"] +
    '\n  Date of Expiry : ' + crl["nextUpdate"] +
    '\n';

  # Store this report for use when we walk through all the hosts/ports.
  crls[url] = report;
}

if (max_index(keys(crls)) == 0)
  exit(0, "No CRLs were successfully parsed.");

# Get the list of hosts with certs with CRLs.
hosts = get_global_kb_list("SSL/CRL/Host");
if (isnull(hosts))
  exit(0, "No hosts were found in the global KB.");
hosts = list_uniq(make_list(hosts));

foreach host (hosts)
{
  ports = get_global_kb_list("SSL/CRL/" + host);
  if (isnull(ports))
    continue;
  ports = list_uniq(make_list(ports));

  foreach port (ports)
  {
    kb = "SSL/CRL/" + host + "/" + port;
    certs = get_global_kb_list(kb);
    if (isnull(certs))
      continue;
    certs = list_uniq(sort(make_list(certs)));

    # Create a single, consolidated report for this port.
    report = make_list();
    foreach cert (certs)
    {
      url  = get_global_kb_item(kb + "/" + cert + "/URL");
      subj = get_global_kb_item(kb + "/" + cert + "/Subject");
      if (isnull(url) || isnull(subj))
        continue;

      info = crls[url];
      if (isnull(info))
        continue;

      info = str_replace(string:info, find:"{{SUBJECT}}", replace:subj);
      report = make_list(report, info);
    }

    if (max_index(report) != 0)
      security_report(host:host, port:port, level:0, extra:join(report, sep:'\n'));
  }
}
