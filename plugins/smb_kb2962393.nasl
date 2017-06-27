#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73865);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"MS KB2962393: Update for Vulnerability in Juniper Networks Windows In-Box Junos Pulse Client (Heartbleed)");
  script_summary(english:"Checks the file timestamps.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has VPN client software installed that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing KB2962393, which resolves an OpenSSL
information disclosure vulnerability (Heartbleed) in the Juniper VPN
client software shipped with Windows 8.1.");
  script_set_attribute(attribute:"see_also", value:"https://iam-fed.juniper.net/auth/xlogin.html");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2962393");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB2962393.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("datetime.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit('SMB/ProductName');
if ("Windows 8.1" >!< productname ) audit(AUDIT_OS_NOT, "Microsoft Windows 8.1");

windir = hotfix_get_systemroot();
hotfix_check_fversion_init();
if (!windir) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:windir);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

file_path = hotfix_append_path(path:windir, value:"System32\Kernel32.dll");
driver_stl = hotfix_get_fversion(path:file_path);

hotfix_handle_error(error_code:driver_stl['error'], file:file_path, exit_on_fail:TRUE);
hotfix_check_fversion_end();

kernel_ver = join(driver_stl['value'], sep:'.');
arch = get_kb_item_or_exit('SMB/ARCH');

filename1 = hotfix_append_path(path:windir, value:"vpnplugins\juniper\JunosPulseVpnBg.dll");
file_timestamp = hotfix_get_timestamp(path:filename1);

hotfix_handle_error(error_code:file_timestamp['error'],
                    file:filename1,
                    appname:"Junos Pulse VPN Client",
                    exit_on_fail:false);

timestamp1 = file_timestamp['value'];

filename2 = hotfix_append_path(path:windir, value:"System32\Mrmcorer.dll");
file_timestamp = hotfix_get_timestamp(path:filename2);

hotfix_handle_error(error_code:file_timestamp['error'],
                    file:filename2,
                    appname:"Microsoft Windows MRM",
                    exit_on_fail:false);

timestamp2 = file_timestamp['value'];

hotfix_check_fversion_end();

filename = filename1;
cur_ts = int(timestamp1);
fix_ts = NULL;
req_kb = '2962140';

# with KB2919355
if(kernel_ver =~ "^6\.3\.9600\.17" && arch == "x64")
{
  fix_ts = 1394542933;
  filename = filename2;
  cur_ts = int(timestamp2);
}
else if(kernel_ver =~ "^6\.3\.9600\.17" && arch == "x86")
{
  fix_ts = 1398036128;
}
# without KB2919355
else if(kernel_ver =~ "^6\.3\.9600\.16" && arch == "x64")
{
  fix_ts = 1398897861;
  req_kb = '2964757';
}
else if(kernel_ver =~ "^6\.3\.9600\.16" && arch == "x86")
{
  fix_ts = 1398879468;
  req_kb = '2964757';
}

if (isnull(fix_ts)) audit(AUDIT_HOST_NOT, 'affected');

if (cur_ts < fix_ts)
{
  port = kb_smb_transport();
  report =
    '\n  File              : ' + filename +
    '\n  File timestamp    : ' + strftime(cur_ts) +
    '\n  Fixed timestamp   : ' + strftime(fix_ts) +
    '\n  Missing KB update : ' + req_kb + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_HOST_NOT, 'affected');
