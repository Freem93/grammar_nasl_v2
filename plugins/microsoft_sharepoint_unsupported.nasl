#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74251);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_name(english:"Microsoft SharePoint Server Unsupported Version Detection");
  script_summary(english:"Checks SharePoint Server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an unsupported version of a document sharing
application.");
  script_set_attribute(attribute:"description", value:
"The remote host has an unsupported version of SharePoint Server
installed.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/lifecycle/search?sort=PN&alpha=Sharepoint");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version of SharePoint Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_portal_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("microsoft_sharepoint_installed.nbin");
  script_require_keys("SMB/Microsoft SharePoint/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Microsoft SharePoint/Installed");
installs = get_kb_list_or_exit("SMB/Microsoft SharePoint/*/Path");

vuln = 0;
foreach install (keys(installs))
{
  edition = '';

  path = installs[install];
  version = install - "SMB/Microsoft SharePoint/";
  version = version - "/Path";
  sp = get_kb_item("SMB/Microsoft SharePoint/"+version+"/SP");
  edition = get_kb_item("SMB/Microsoft SharePoint/"+version+"/Edition");

  if (!isnull(sp))
  {
    sp = int(sp);
    if (version == '2003')
    {
      tmp_ver = version;
      if (sp > 0) tmp_ver += ":sp" + sp;

      register_unsupported_product(product_name:"Micorosft SharePoint Server",
                                   cpe_base:"microsoft:sharepoint_server", version:tmp_ver);

      info +=
        '\n  Path              : ' + path +
        '\n  Installed version : Microsoft SharePoint ' + edition + ' 2003 Service Pack ' + sp +
        '\n  Fixed version     : This version is no longer supported.\n';
      vuln++;
    }
    else if (version == '2007' && int(sp) < 3)
    {
      tmp_ver = version;
      if (sp > 0) tmp_ver += ":sp" + sp;

      register_unsupported_product(product_name:"Micorosft SharePoint Server",
                                   cpe_base:"microsoft:sharepoint_server", version:tmp_ver);

      info +=
        '\n  Path              : ' + path +
        '\n  Installed version : Microsoft SharePoint ' + edition + ' 2007 Service Pack ' + sp +
        '\n  Fixed version     : Microsoft SharePoint ' + edition + ' 2007 Service Pack 3\n';
      vuln++;
    }
    else if (version == '2010' && int(sp) < 2)
    {
      tmp_ver = version;
      if (sp > 0) tmp_ver += ":sp" + sp;

      register_unsupported_product(product_name:"Micorosft SharePoint Server",
                                   cpe_base:"microsoft:sharepoint_server", version:tmp_ver);

      info +=
        '\n  Path              : ' + path +
        '\n  Installed version : Microsoft SharePoint ' + edition + ' 2010 Service Pack ' + sp +
        '\n  Fixed version     : Microsoft SharePoint ' + edition + ' 2010 Service Pack 2\n';
      vuln++;
    }
  }
}

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's were';
    else s = ' was';

    report =
      '\n' + 'The following unsupported SharePoint Server install' + s + ' detected on' +
      '\n' + 'the remote host :' +
      '\n' +
      '\n' + info + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
