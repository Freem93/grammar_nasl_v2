#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3208) exit(0);

include("compat.inc");

if (description)
{
  script_id(56284);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"SSL Certificate Fails to Adhere to Basic Constraints / Key Usage Extensions");
  script_summary(english:"Checks that the certificate chain adheres to all basic constraints and key usage extensions.");

  script_set_attribute(attribute:"synopsis", value:
"An X.509 certificate in the chain used by this service fails to
adhere to all of its basic constraints and key usage extensions.");
  script_set_attribute(attribute:"description", value:
"An X.509 certificate sent by the remote host contains one or more
violations of the restrictions imposed on it by RFC 5280.  This means
that either a root or intermediate Certificate Authority signed a
certificate incorrectly.

Certificates that fail to adhere to the restrictions in their
extensions may be rejected by certain software.  The existence of such
certificates indicates either an oversight in the signing process, or
malicious intent.");

  script_set_attribute(attribute:"solution", value:
"Alter the offending certificate's extensions and have it signed
again.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc5280.txt");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/Extension/BasicConstraints");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has unused certificates from the KB.
key = "SSL/Chain/Extension/BasicConstraints";
port = get_kb_item_or_exit(key);
key += "/" + port + "/";

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

# Initialize the report.
report = "";

# Get the key indexes of the certificates that got flagged.
idxs = get_kb_list_or_exit(key + "Attributes/*");

foreach idx (keys(idxs))
{
  # Get the report text.
  attr = get_kb_item_or_exit(idx);
  idx = str_replace(string:idx, find:"Attributes", replace:"Reason");
  reason = get_kb_item_or_exit(idx);

  # Format the report text.
  report +=
    '\n' + reason +
    '\n' +
    '\n' + cert_report(attr, chain:FALSE) +
    '\n';
}

security_warning(port:port, extra:report);
