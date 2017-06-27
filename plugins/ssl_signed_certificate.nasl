#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(51192);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2017/05/18 20:59:33 $");

 script_name(english:"SSL Certificate Cannot Be Trusted");
 script_summary(english:"Checks that the service's certificate can be trusted.");

 script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service cannot be trusted.");
 script_set_attribute(attribute:"description", value:
"The server's X.509 certificate cannot be trusted. This situation can
occur in three different ways, in which the chain of trust can be
broken, as stated below :

  - First, the top of the certificate chain sent by the
    server might not be descended from a known public
    certificate authority. This can occur either when the
    top of the chain is an unrecognized, self-signed
    certificate, or when intermediate certificates are
    missing that would connect the top of the certificate
    chain to a known public certificate authority.

  - Second, the certificate chain may contain a certificate
    that is not valid at the time of the scan. This can
    occur either when the scan occurs before one of the
    certificate's 'notBefore' dates, or after one of the
    certificate's 'notAfter' dates.

  - Third, the certificate chain may contain a signature
    that either didn't match the certificate's information
    or could not be verified. Bad signatures can be fixed by
    getting the certificate with the bad signature to be
    re-signed by its issuer. Signatures that could not be
    verified are the result of the certificate's issuer
    using a signing algorithm that Nessus either does not
    support or does not recognize.

If the remote host is a public host in production, any break in the
chain makes it more difficult for users to verify the authenticity and 
identity of the web server. This could make it easier to carry out 
man-in-the-middle attacks against the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.itu.int/rec/T-REC-X.509/en");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/X.509");
 script_set_attribute(attribute:"solution", value:
"Purchase or generate a proper certificate for this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15"); 

 script_set_attribute(attribute:"plugin_type", value:"remote"); 
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "General");

 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

 script_dependencies("ssl_certificate_chain.nasl");
 script_require_keys("SSL/BrokenCAChain");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

global_var port, singular;

function make_report()
{
  local_var attr, attrs, certs, key;

  key = _FCT_ANON_ARGS[0];

  # Get the list of certificates that were unused.
  certs = get_kb_list("SSL/Chain/" + key + "/" + port);
  if (isnull(certs))
    return NULL;

  attrs = make_list();
  foreach attr (certs)
  {
    attrs = make_list(attrs, attr);
  }

  singular = (max_index(attrs) == 1);

  return cert_report(attrs, chain:FALSE);
}

# Get the port that has a broken certificate chain from the KB.
port = get_kb_item_or_exit("SSL/BrokenCAChain");

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

reports = "";

# Report certificates that were signed using unknown algorithms.
report = make_report("Signature/Algorithm/Unknown");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it has a signature that uses an' +
      '\nalgorithm that Nessus does not recognize :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have signatures that use algorithms' +
      '\nthat Nessus does not recognize :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that were signed using unsupported algorithms.
report = make_report("Signature/Algorithm/Unsupported");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it has a signature that uses an' +
      '\nalgorithm that this version of Nessus does not support :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have signatures that use algorithms' +
      '\nthat this version of Nessus does not support :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that were signed using ECDSA with a curve we
# don't recognize.
report = make_report("Signature/Curve/Unrecognized");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it has a signature that uses an' +
      '\nelliptic curve that this version of Nessus does not recognize :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have signatures that use' +
      '\nelliptic curves that this version of Nessus does not recognize :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that do not have a valid signature.
report = make_report("Signature/Bad");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it has an invalid signature :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have invalid signatures :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that have a 'not before' date in the future.
report = make_report("Expiry/Before");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it is not yet valid :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they are not yet valid :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that have a 'not after' date in the past.
report = make_report("Expiry/After");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it has expired :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have expired :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that have an unknown root CA.
report = make_report("UnknownCA");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was at the top of the certificate' +
      '\nchain sent by the remote host, but it is signed by an unknown' +
      '\ncertificate authority :';
  }
  else
  {
    reports +=
      '\nThe following certificates were at the top of the certificate' +
      '\nchain sent by the remote host, but they are signed by unknown' +
      '\ncertificate authorities :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that have invalid OCSP status'
report = make_report("OCSP/Status");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but has it been flagged by OCSP :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have been flagged by OCSP :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

# Report certificates that have invalid OCSP signatures
report = make_report("OCSP/Signature");
if (report)
{
  if (singular)
  {
    reports +=
      '\nThe following certificate was part of the certificate chain' +
      '\nsent by the remote host, but it has an invalid OCSPResponse' +
      '\nsignature :';
  }
  else
  {
    reports +=
      '\nThe following certificates were part of the certificate chain' +
      '\nsent by the remote host, but they have invalid OCSPResponse' +
      '\nsignatures :';
  }

  reports +=
    '\n' +
    '\n' + report;
}

security_warning(port:port, extra:reports);
