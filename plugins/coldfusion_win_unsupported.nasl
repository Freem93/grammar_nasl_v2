#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72093);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/31 03:40:07 $");

  script_name(english:"Adobe ColdFusion Unsupported Version Detection (credentialed check)");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a web application
platform.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe ColdFusion running
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html#sort-a");
  # http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59405f25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe ColdFusion that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_ports("SMB/coldfusion/instance");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

# Get SMB-detected installs
instance_name = get_kb_item_or_exit("SMB/coldfusion/instance");
version = get_kb_item_or_exit("SMB/coldfusion/"+instance_name+"/version");
path = get_kb_item_or_exit("SMB/coldfusion/"+instance_name+"/cfroot");
build = get_kb_item("SMB/coldfusion/"+instance_name+"/build");

if (!build) build = "0";

longterm_support_lists = make_array(
  "^[0-6]($|\.)", make_array(
        'support_type' , 'out_of_support',
        'support_dates', 'No support dates are available.',
        'support_url'  , 'http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63'
      ),
  "^7($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2010-02-07 (end of regular support) / 2012-02-07 (end of Extended Support)',
        'support_url'  , 'http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63'
      ),
  "^8($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2012-07-31 (end of regular support) / 2014-07-31 (end of Extended Support)',
        'support_url'  , 'http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63'
      ),
  "^9($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2014-12-31 (end of regular support) / 2016-12-31 (end of Extended Support)',
        'support_url'  , 'http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63'
      )
#  "^10($|\.)",  make_array(
#        'support_type' , NULL,
#        'support_dates', '2017-05-16 (end of regular support) / 2019-05-16 (end of Extended Support)',
#        'support_url'  , 'http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63'
#      )
#  "^11($|\.)",  make_array(
#        'support_type' , NULL,
#        'support_dates', '2019-04-30 (end of regular support) / 2021-04-30 (end of Extended Support)',
#        'support_url'  , 'http://www.adobe.com/support/products/enterprise/eol/eol_matrix.html#63'
#      )

);

supported_versions = '10.x / 11.x / 2016';

# Determine support status.
obsolete = '';
foreach v (keys(longterm_support_lists))
{
  if (version =~ v)
  {
    if (longterm_support_lists[v]['support_type'] == "extended_support")
      set_kb_item(
        name:"SMB/coldfusion/"+longterm_support_lists[v]['support_type']+"/"+path+"/"+version+"."+build,
        value:longterm_support_lists[v]['support_dates']
      );
    else
      obsolete = v;

    break;
  }
}

if (obsolete)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  register_unsupported_product(product_name:"Adobe ColdFusion",
                               version:version, cpe_base:"adobe:coldfusion");

  if (report_verbosity > 0)
  {
    info =
      '\n  Path                : ' + path  +
      '\n  Installed version   : ' + version + "." + build;

    if (longterm_support_lists[v]['support_dates'])
      info += '\n  Support dates       : ' + longterm_support_lists[v]['support_dates'];
    if (longterm_support_lists[v]['support_url'])
      info += '\n  Announcement        : ' + longterm_support_lists[v]['support_url'];
    info += '\n  Supported versions  : ' + supported_versions + '\n';

    security_hole(port:port, extra:info);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "ColdFusion", version, path);
