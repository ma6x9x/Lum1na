#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Loads the a-Shell mini ios_system runtime and prepares its environment.
FOUNDATION_EXPORT BOOL WQTerminalPrepare(void);

/// Creates a PTY-backed in-process shell. Returns the master descriptor and
/// writes a harmless fake pid to pidOut (the terminal UI only uses it for a
/// stop button; there is no child process).
FOUNDATION_EXPORT int WQTerminalSpawnShell(int * _Nullable pidOut,
                                           NSString * _Nullable chdirPath);

/// Runs a terminal self-test when WQ_TEST_TERMINAL is set in the environment.
FOUNDATION_EXPORT void WQTerminalSelfTest(void);
FOUNDATION_EXPORT void WQTerminalPresentTestUI(void);

NS_ASSUME_NONNULL_END
