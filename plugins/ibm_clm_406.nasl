#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72929);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2014-0862");
  script_bugtraq_id(65900);
  script_osvdb_id(103868);

  script_name(english:"IBM Rational Collaborative Lifecycle Management Products Unspecified Remote Code Execution");
  script_summary(english:"Checks version of IBM CLM components");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of at least one IBM Rational Collaborative Lifecycle
Management component installed on the remote Windows host is 3.x prior
to 3.0.1.6 iFix2 or 4.x prior to 4.0.6.  It is, therefore, potentially
affected by an unspecified remote code execution vulnerability in the
Jazz Team Server.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21664566");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM CLM 3.0.1.6 iFix2 / 4.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_collaborative_lifecycle_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_collaborative_lifecycle_management_installed.nbin");
  script_require_keys("SMB/IBM CLM/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

paths = get_kb_list_or_exit("SMB/IBM CLM/Path");
paths = list_uniq(make_list(paths));

foreach path (paths)
{
  products = get_kb_list("SMB/IBM CLM/"+path+"/Components/*");
  if (products)
  {
    foreach product (keys(products))
    {
      version = products[product];
      product = product - ("SMB/IBM CLM/" + path + "/Components/");

      if (
        (
          'Required Base License Keys' >!< product &&
          'Trial keys for' >!< product
        ) &&
        (
          'Quality Management' >< product ||
          'Requirements Management' >< product ||
          'Change and Configuration Management' >< product ||
          ('Jazz Team Server and' >< product && ('CCM' >< product || 'QM' >< product || 'RM' >< product))
        )
      )
      {
        if (version =~ '^3\\.0\\.')
        {
          matches = eregmatch(pattern:'^([0-9\\.]+)( iFix ([0-9]+))?', string:version);
          if (matches)
          {
            ver = matches[1];
            if (max_index(matches) > 3)
              ifix = int(matches[3]);
            else
              ifix = 0;

            if (
              (ver_compare(ver:ver, fix:'3.0.1.6') < 0) ||
              (ver_compare(ver:ver, fix:'3.0.1.6') == 0 && ifix < 2)
            )
            {
              info +=
                '\n  Path              : ' + path +
                '\n  Component         : ' + product +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 3.0.1.6 iFix 2\n';
            }
          }
        }
        else if (version =~ '^4\\.0\\.')
        {
          if (ver_compare(ver:version, fix:'4.0.6') < 0)
          {
            info +=
              '\n  Path              : ' + path +
              '\n  Component         : ' + product +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 4.0.6\n';
          }
        }
      }
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, 'IBM Collaborative Lifecycle Management Application');
