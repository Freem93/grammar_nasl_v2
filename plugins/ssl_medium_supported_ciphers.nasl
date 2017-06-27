#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42873);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/23 19:56:24 $");

  script_name(english:"SSL Medium Strength Cipher Suites Supported");
  script_summary(english:"Reports supported medium strength SSL cipher suites.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of medium strength SSL ciphers.");
  script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer medium
strength encryption. Nessus regards medium strength as any encryption
that uses key lengths at least 64 bits and less than 112 bits, or else
that uses the 3DES encryption suite.

Note that it is considerably easier to circumvent medium strength
encryption if the attacker is on the same physical network.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application if possible to avoid use of
medium strength ciphers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

supported_ciphers = get_kb_list_or_exit("SSL/Ciphers/" + port);
supported_ciphers = make_list(supported_ciphers);
if (!max_index(supported_ciphers)) exit(0, "No ciphers were found for port " + port + ".");

# Generate the report of supported medium strength ciphers.
report = cipher_report(supported_ciphers, eq:CIPHER_STRENGTH_MEDIUM);
if (isnull(report)) exit(0, "No medium strength SSL ciphers are supported on port " + port + ".");

if (report_verbosity > 0)
{
  report =
    '\nHere is the list of medium strength SSL ciphers supported by the remote server :' +
    '\n' + report;

  security_warning(port:port, extra:report);
}
else security_warning(port);
