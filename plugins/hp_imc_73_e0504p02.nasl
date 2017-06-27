#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99030);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id(
    "CVE-2017-5791",
    "CVE-2017-5793",
    "CVE-2017-5794",
    "CVE-2017-5795"
  );
  script_bugtraq_id(
    96773,
    96815
  );
  script_osvdb_id(
    153398,
    153419,
    153569,
    153570
  );
  script_xref(name:"HP", value:"HPESBHF03714");
  script_xref(name:"HP", value:"HPESBHF03715");
  script_xref(name:"HP", value:"HPESBHF03716");
  script_xref(name:"HP", value:"HPESBHF03717");
  script_xref(name:"HP", value:"emr_na-hpesbhf03714en_us");
  script_xref(name:"HP", value:"emr_na-hpesbhf03715en_us");
  script_xref(name:"HP", value:"emr_na-hpesbhf03716en_us");
  script_xref(name:"HP", value:"emr_na-hpesbhf03717en_us");
  script_xref(name:"ZDI", value:"ZDI-17-161");
  script_xref(name:"ZDI", value:"ZDI-17-163");
  script_xref(name:"ZDI", value:"ZDI-17-164");
  script_xref(name:"ZDI", value:"ZDI-17-165");

  script_name(english:"HPE Intelligent Management Center 7.2 E0403P06 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HPE Intelligent Management Center.");

  script_set_attribute(attribute:"synopsis", value:
"The version of HPE Intelligent Management Center on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Intelligent Management Center (IMC) running on the
remote host is version 7.2 E0403P06. It is, therefore, affected by
multiple vulnerabilities :

  - A flaw exists in UrlAccessController when handling URIs
    with the doFilter() method. A remote attacker can
    exploit this, via a specially crafted request, to bypass
    authorization. (CVE-2017-5791)

  - A flaw exists in CommonUtils due to improper
    sanitization of user-supplied input before using it in
    file operations. An authenticated, remote attacker can
    exploit this issue, via a specially crafted request that
    uses path traversal, to upload arbitrary files, which
    can then be used to execute arbitrary code.
    (CVE-2017-5793)

  - A flaw exists in FileUploadServlet due to improper
    sanitization of user-supplied input before using it in
    file operations. An authenticated, remote attacker can
    exploit this issue, via a specially crafted request that
    uses path traversal, to upload arbitrary files, which
    then can be used to execute arbitrary code.
    (CVE-2017-5794)

  - A flaw exists in FileDownloadServlet due to improper
    sanitization of user-supplied input to the 'fileName'
    parameter before using it in file operations. An
    authenticated, remote attacker can exploit this issue,
    via a specially crafted request that uses path
    traversal, to disclose the content of arbitrary files.
    (CVE-2017-5795)");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03714en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dd0c802");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03715en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?654ac617");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03716en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6c1d9a5");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03717en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa7e8481");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-161/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-163/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-164/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-165/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HPE Intelligent Management Center version 7.3 E0504P02 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies('hp_imc_detect.nbin');
  script_require_ports('Services/activemq', 61616);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to use
port = get_service(svc:'activemq', default:61616, exit_on_fail:TRUE);
version = get_kb_item_or_exit('hp/hp_imc/'+port+'/version');

# Only 7.2-E0403P06 is affected, according to HP advisories
if (toupper(version) != "7.2-E0403P06")
  audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center', port, version);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 7.3-E0504P02' +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
