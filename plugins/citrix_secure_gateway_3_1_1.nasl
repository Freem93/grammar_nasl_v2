#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52546);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2009-2214");
  script_bugtraq_id(35421);
  script_osvdb_id(55156);
  script_xref(name:"Secunia", value:"35503");

  script_name(english:"Citrix Secure Gateway Unspecified DoS");
  script_summary(english:"Checks version of CSG");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A gateway application on the remote host has an unspecified denial of
service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Citrix Secure Gateway running on the remote host
has an unspecified denial of service vulnerability.  Making a
specially crafted request can result in 100% CPU utilization, causing
the application to become unresponsive. 

A remote attacker could exploit this by sending a malicious request
that could cause the application to stop accepting subsequent
connections."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.citrix.com/article/CTX121172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.citrix.com/article/CTX121012"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Citrix Secure Gateway 3.1.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:secure_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_secure_gateway_installed.nasl");
  script_require_keys("SMB/citrix_secure_gateway/path", "SMB/citrix_secure_gateway/ver");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


path = get_kb_item_or_exit('SMB/citrix_secure_gateway/path');
ver = get_kb_item_or_exit('SMB/citrix_secure_gateway/ver');
fix = '3.1.1';

# The vendor says "This vulnerability is present in all versions of
# Citrix Secure Gateway up to and including version 3.1."
if (ver_compare(ver:ver, fix:fix, strict:FALSE) != -1) exit(0, 'CSG version ' + ver + ' is not affected.');

port = get_kb_item("SMB/transport");

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

