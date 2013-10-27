
dnl
dnl SAD_MESSAGE(MESSAGE)
dnl

AC_DEFUN(SAD_MESSAGE,[
   AC_MSG_RESULT()
   AC_MSG_RESULT(${SB}$1...${EB})
   AC_MSG_RESULT()
])

dnl
dnl SAD_CHECK_OPTION(STRING, VAR)
dnl

AC_DEFUN(SAD_CHECK_OPTION,[
   echo "$1 ${SB}$2${EB}"
])


dnl
dnl SAD_LINUX_KERNEL()
dnl

AC_DEFUN(SAD_LINUX_KERNEL,[

   AC_MSG_CHECKING(Linux kernel version)
   major=`uname -r  | cut -f1 -d"."`
   minor=`uname -r  | cut -f2 -d"."`
   uname=`uname -r`
   AC_MSG_RESULT($uname)
   if test "$major$minor" -lt 24; then
      AC_MSG_WARN(*******************************);
      AC_MSG_WARN(* Kernel >= 2.4.x REQUIRED !! *);
      AC_MSG_WARN(*******************************);
      exit;
   fi
])


dnl vim:ts=3:expandtab
