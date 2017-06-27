#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52547);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/15 16:37:16 $");

  script_bugtraq_id(46596);
  script_xref(name:"Secunia", value:"43497");

  script_name(english:"Citrix Secure Gateway Unspecified Remote Code Execution");
  script_summary(english:"Checks version of CSG");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A gateway application on the remote host has an unspecified code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Citrix Secure Gateway running on the remote host
has an unspecified code execution vulnerability.  This could
reportedly allow a remote attacker to execute arbitrary code in the
context of the Secure Gateway process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.citrix.com/article/CTX128168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.citrix.com/article/CTX127793"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Citrix Secure Gateway 3.1.5 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:secure_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("citrix_secure_gateway_installed.nasl");
  script_require_keys("SMB/citrix_secure_gateway/path", "SMB/citrix_secure_gateway/ver");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


path = get_kb_item_or_exit('SMB/citrix_secure_gateway/path');
ver = get_kb_item_or_exit('SMB/citrix_secure_gateway/ver');
fix = '3.1.5';

# according to the vendor only 3.1.4 is affected
if (ver != '3.1.4') exit(0, 'CSG version ' + ver + ' is not affected.');

port = get_kb_item("SMB/transport");

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
