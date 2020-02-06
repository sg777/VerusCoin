@echo off
call :GET_CURRENT_DIR
cd %THIS_DIR%
IF NOT EXIST "%APPDATA%"\ZcashParams (
MKDIR "%APPDATA%"\ZcashParams
)

FOR %%F IN (sprout-proving.key, sprout-verifying.key, sapling-spend.params, sapling-output.params, sprout-groth16.params) DO (
    IF NOT EXIST "%APPDATA%"\ZcashParams\%%F  (
        ECHO Downloading Zcash trusted setup sprout-verifying.key, this may take a while ...
	        curl --output "%APPDATA%"\ZcashParams \
            -# -L -C - \
            https://z.cash/downloads/%%F
    )
)

goto :EOF
:GET_CURRENT_DIR
pushd %~dp0
set THIS_DIR=%CD%
popd
goto :EOF
