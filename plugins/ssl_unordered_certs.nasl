#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(56471);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/01/17 17:18:31 $");

  script_name(english:"SSL Certificate Chain Not Sorted");
  script_summary(english:"Checks that the certificate chain is in ascending order.");

  script_set_attribute(attribute:"synopsis", value:
"The X.509 certificate chain used by this service contains
certificates that aren't in order.");
  script_set_attribute(attribute:"description", value:
"At least one of the X.509 certificates sent by the remote host is not
in order.  Some certificate authorities publish certificate bundles
that are in descending instead of ascending order, which is incorrect
according to RFC 4346, Section 7.4.2. 

Some SSL implementations, often those found in embedded devices,
cannot handle unordered certificate chains.");
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc4346.txt");
  script_set_attribute(attribute:"solution", value:
"Reorder the certificates in the certificate chain.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/Unordered");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has an unordered certificate chain from the KB.
key = "SSL/Chain/Unordered";
port = get_kb_item_or_exit(key);
key += "/" + port + "/";

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_note(port);
  exit(0);
}

# Initialize the report.
report = "";

# Get the key indexes of the certificates that got flagged.
idxs = get_kb_list_or_exit(key + "*");

# Collect the attributes from the KB.
attrs = make_list();
for (i = 0; TRUE; i++)
{
  attr = idxs[key + i];
  if (isnull(attr))
    break;

  attrs = make_list(attrs, attr);
}

# Report our findings.
report =
  '\nThe certificate chain sent by the remote host is not in order : ' +
  '\n' +
  '\n' + cert_report(attrs);

security_note(port:port, extra:report);
