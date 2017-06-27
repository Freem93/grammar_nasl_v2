#TRUSTED 3de048953bc320f5f2e70082fdab67f0e2f5095f4cd94996db5ee76654c5f9d71bd3d426aea727c4f182d575e54768ad60856e2bacbb92f1b17943de5cef4b946d25036d4ee0e655bec35e531e545de1e48c3faf8f7abc2210e597112fe7a92155e64bbcf29049a20e83c5620331319df780bf57b025da3fd49f257329b63f2b4c7e9fffa2311fe905c2086fd4ce665cb00951ecbf201e56e0361fd667f8fe53e17c495eeb8629730ffc91ef0ff0559840765327d0e5b3fc73d469a6c5aa6fac195b51d5b2deab0e642029236839bd01017b1ff5dc1fc7eda84cd9e419b4e0ccee03a12937c3bea2e948047c558814496fc3a5a3c478ffc37237477d51e1dd8cfa588fd96d65794d0bb498e977e7f5cfdc1d09b38739568d303b6fd0b279e9856ef766d12fc19a6893c41d81a39bc9dbcdea588bb985f98199de701c108bfa71c016abca9f292f67c6859fcb78eaf30f8cd1213c7f2b59ff441d358fa2128ad492594ec567844eafc49ae7d38dfc04a28546a4ccdc4d2b2b950076d30d293aedf64b4edc89282487a11aa10506d938f03d82dff1bc8d33646e09faef27c8e39738bb8220279c8ea492e1fad84fd5c83fe32bc71cac12ddbc5a920e60c1ae2e7e7b6b1e4f23e6cb4bd7eca50f47674412cd658a470f536cecf9b8781b3c65602e5580a919e56a7775f2531e73ea8eea2bdfb2da2e8da35c5fc7531b641a276f1b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24812);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

 script_cve_id("CVE-2007-0051");
 script_bugtraq_id(21871);
 script_osvdb_id(31165);

 script_name(english:"iPhoto < 6.0.6");
 script_summary(english:"Check for iPhoto 6.0.6");

 script_set_attribute(attribute:"synopsis", value:
"The remote system is missing a security update");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 6 that is older than
version 6.0.6.  As such, it contains a security vulnerability that may
allow an attacker to execute arbitrary code on this host. 

To exploit this flaw, an attacker would need to lure a user on the
remote host into subscribing to a malicious photocast album");
 script_set_attribute(attribute:"solution", value:
"http://docs.info.apple.com/article.html?artnum=305215");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305215");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:iphoto");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }

 if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");
 if ( buf )
 {
  vers = split(buf, sep:'.', keep:FALSE);
  if ( int(vers[0]) == 6 && int(vers[1]) == 0 && int(vers[2]) < 6  ) security_warning(0);
 }
}
