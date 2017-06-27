#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62777);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/05/23 15:38:26 $");

  script_cve_id("CVE-2011-2592", "CVE-2011-2593");
  script_bugtraq_id(54754);
  script_osvdb_id(84433);
  script_xref(name:"Secunia", value:"45299");
  script_xref(name:"IAVB", value:"2012-B-0077");

  script_name(english:"Citrix Access Gateway Plug-in for Windows ActiveX Control StartEPA() Method HTTP Response Header Parsing Overflows (CTX134303)");
  script_summary(english:"Checks control's version / kill bit");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Citrix Access Gateway ActiveX control for Citrix Access Gateway
Enterprise Edition is installed on the remote Windows host.  It is the
ActiveX component of the Citrix Access Gateway Plug-in for Windows and
provides an SSL-based VPN via a web browser.

The installed version of this control (nsepa.exe) is affected by the
following vulnerabilities involving the 'StartEPA()' method that could
lead to arbitrary code execution :

  - A boundary error exists that can be exploited to cause
    a heap-based buffer overflow when processing overly
    long 'CSEC' HTTP response headers. (CVE-2011-2592)

  - An integer overflow exists that can be exploited to
    cause a heap-based buffer overflow when processing
    specially crafted 'Content-Length' HTTP response
    headers. (CVE-2011-2593)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523728/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523729/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX134303");
  script_set_attribute(
    attribute:"solution",
    value:
"Update to version 9.3-57.5 / 10.0-69.4 or set the kill bit for the
control."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:access_gateway");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) audit(code:1, AUDIT_FN_FAIL, 'activex_init');


# Test each control
info = "";
clsids = make_list(
  # 9.x
  '{391DFC1F-B9B9-4A3D-A352-9A541A3630A6}',
  # 10.x
  '{69B69991-62EC-4b51-9E72-8FC664BEC7DB}'
);

not_vuln_ver_installed = FALSE;

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    audit(AUDIT_FN_FAIL, 'activex_get_filename', 'NULL');
  }
  if (!file) continue;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);
  if (!version)
  {
    activex_end();
    audit(AUDIT_VER_FAIL, file);
  }
  ver_pat = "^([0-9]+\.[0-9]+)\.([0-9]+\.[0-9]+)$";
  version_ui = ereg_replace(pattern:ver_pat, replace:"\1-\2", string:version);

  ver = split(version,sep:'.', keep:FALSE);
  for (x=0; x<max_index(ver); x++)
    ver[x] = int(ver[x]);

  # And check it.
  # Affected versions :
  #   10.x < 10.0-69.4
  #   9.x < 9.3-57.5
  if (
    (
      clsid == '{69B69991-62EC-4b51-9E72-8FC664BEC7DB}' &&
      ver[0] == 10 && ver[1] == 0 &&
      (
        ver[2] < 69 ||
        (
          ver[2] == 69 && ver[3] < 4
        )
      )
    ) ||
    (
      clsid == '{391DFC1F-B9B9-4A3D-A352-9A541A3630A6}' &&
      ver[0] == 9 &&
      (
        ver[1] < 5 ||
        (
          ver[1] == 5 &&
          (
            ver[2] < 57 ||
            (
              ver[2] == 57 && ver[3] < 5
            )
          )
        )
      )
    )
  )
  {
    vuln_version = TRUE;
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      info = '\n  Class identifier  : ' + clsid +
             '\n  Filename          : ' + file +
             '\n  Installed version : ' + version_ui +
             '\n  Fixed version     : 9.3-57.5 / 10.0-69.4\n';
    }
  }
  else
  {
    not_vuln_ver_installed = TRUE;
    not_vuln_version = version_ui;
    not_vuln_path = file;
  }
}
activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  if (vuln_version == TRUE) audit(AUDIT_ACTIVEX, version_ui);
  else
  {
    if (not_vuln_ver_installed) audit(AUDIT_INST_PATH_NOT_VULN, "'nsepa.exe'", not_vuln_version, not_vuln_path);
    else audit(AUDIT_NOT_INST, "'nsepacom' control");
  }
}
