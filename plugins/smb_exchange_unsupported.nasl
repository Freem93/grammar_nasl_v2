#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6000 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(22313);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/04/10 18:41:59 $");

  script_name(english:"Microsoft Exchange Server Unsupported Version Detection");
  script_summary(english:"Determines the remote version of Exchange.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Exchange Server on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Exchange Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/gp/lifeselectindex");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("installed_sw/Microsoft Exchange");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

install = get_single_install(app_name:"Microsoft Exchange", exit_if_unknown_ver:TRUE);

port = get_kb_item("SMB/transport");
if(isnull(port)) port = 445;

report = "";

path = install["path"];

ver = get_kb_item_or_exit("SMB/Exchange/Version");
sp = get_kb_item("SMB/Exchange/SP");
if(isnull(sp)) sp = 0;

if (!empty_or_null(install["CU"]))
  cu = install["CU"];

# Exchange 2000
if ( ver == 60 )
{
 tmp_ver = "2000";
 if (sp > 0) tmp_ver += ":sp" + sp;
 register_unsupported_product(product_name:"Microsoft Exchange Server",
                              cpe_base:"microsoft:exchange_server", version:tmp_ver);
 report =
'The remote host is running Microsoft Exchange Server 2000 SP' + sp + '.\n' +
'Microsoft Exchange Server 2000 is no longer supported.';
 security_hole(port:port, extra:report);
 exit(0);
}

# Exchange 2003
if ( ver == 65 )
{
 tmp_ver = "2003";
 if (sp > 0) tmp_ver += ":sp" + sp;
 register_unsupported_product(product_name:"Microsoft Exchange Server",
                              cpe_base:"microsoft:exchange_server", version:tmp_ver);

 report =
'The remote host is running Microsoft Exchange Server 2003 SP' + sp + '.\n' +
'Microsoft Exchange Server 2003 is no longer supported.';
 security_hole(port:port, extra:report);
 exit(0);
}

# Exchange 2007
if ( ver == 80 )
{
 tmp_ver = "2007";
 if (sp > 0) tmp_ver += ":sp" + sp;
 register_unsupported_product(product_name:"Microsoft Exchange Server",
                              cpe_base:"microsoft:exchange_server", version:tmp_ver);

 report =
'The remote host is running Microsoft Exchange Server 2007 SP' + sp + '.\n' +
'Microsoft Exchange Server 2007 is no longer supported.';
 security_hole(port:port, extra:report);
 exit(0);
}

# Exchange 2010
if ( ver == 140 && sp < 3 )
{
 tmp_ver = "2010";
 if (sp > 0) tmp_ver += ":sp" + sp;
 register_unsupported_product(product_name:"Microsoft Exchange Server",
                              cpe_base:"microsoft:exchange_server", version:tmp_ver);

 report =
'The remote host is running Microsoft Exchange Server 2010 SP' + sp + '.\n' +
'Apply Service Pack 3 to be up to date.';
 security_hole(port:port, extra:report);
 exit(0);
}

# Exchange 2013
if ( ver == 150 && (cu != 4 && cu < 11) )
{
 tmp_ver = "2013";
 if (sp > 0) tmp_ver += ":cu" + cu;
 register_unsupported_product(product_name:"Microsoft Exchange Server",
                              cpe_base:"microsoft:exchange_server", version:tmp_ver);

 report =
'The remote host is running Microsoft Exchange Server 2013 CU' + cu + '.\n' +
'Apply Service Pack 1 or the latest Cumulative Update to be up to date.';
 security_hole(port:port, extra:report);
 exit(0);
}

# Exchange 2016
if ( ver == 151 && cu < 2 )
{
 tmp_ver = "2016";
 if (cu > 0) tmp_ver += ":cu" + cu;
 register_unsupported_product(product_name:"Microsoft Exchange Server",
                              cpe_base:"microsoft:exchange_server", version:tmp_ver);

 report =
'The remote host is running Microsoft Exchange Server 2016 CU' + cu + '.\n' +
'Apply Cumulative Update 2 to be up to date.';
 security_hole(port:port, extra:report);
 exit(0);
}

switch (ver)
{
  case 80:
    strVer = 'Exchange 2007 SP' + sp;
    break;

  case 140:
    strVer = 'Exchange 2010 SP' + sp;
    break;

  case 150:
      strVer = 'Exchange 2013 CU' + cu;
    break;

  case 151:
    strVer = 'Exchange 2016 CU' + cu;
    break;
}
audit(AUDIT_INST_VER_NOT_VULN, strVer);
