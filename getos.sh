#!/bin/bash

until [ -z "$1" ]  # Until all parameters used up
do
  case $1 in
    *=*)
      eval $1;
      ;;
    *)
      echo $1 >&2 ;
      ;;
  esac
  shift
done

if $CC -dM -E - < /dev/null | grep __APPLE__ > /dev/null; then
	echo darwin;
	exit;
fi;

if $CC -dM -E - < /dev/null | grep __linux__ > /dev/null; then
	echo linux;
	exit;
fi;

if $CC -dM -E - < /dev/null | grep __WIN32__ > /dev/null; then
	echo win32;
	exit;
fi;

$CC -dM -E - < /dev/null >&2;
echo unkown;
