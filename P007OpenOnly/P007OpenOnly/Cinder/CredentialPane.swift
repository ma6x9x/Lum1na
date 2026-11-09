import SwiftUI
import UniformTypeIdentifiers
import UIKit

// MARK: - Signing credentials pane
//
// LiveContainer / StikDebug-style import + selection, scoped honestly: the
// files are for signing or installing another IPA. The top card shows this
// process's real entitlements, so nobody can mistake a file in Documents for
// an app group on the running signature.

struct CredentialPane: View {
    @ObservedObject private var store = CredentialStore.shared
    @EnvironmentObject private var browser: FileBrowser

    @State private var importing = false
    @State private var unlockTarget: SigningIdentity?
    @State private var password = ""
    @State private var remember = true
    @State private var copied = false
    @State private var liveGroups: [String] = []
    @State private var liveAppID: String?

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                liveCard
                transportCard
                importCard
                identityCard
                profileCard
                checkCard
                handoffCard
            }
            .padding(16)
        }
        .onAppear { refreshLive() }
        .fileImporter(isPresented: $importing,
                      allowedContentTypes: [.data],
                      allowsMultipleSelection: true) { result in
            switch result {
            case .success(let urls):
                _ = store.importFiles(urls)
            case .failure(let error):
                store.note("Import failed: \(error.localizedDescription)")
            }
        }
        .sheet(item: $unlockTarget) { target in
            unlockSheet(target)
        }
    }

    // MARK: Live signature

    private var liveCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 6) {
                SectionLabel(text: "Running signature")
                KeyValueRow(key: "Bundle", value: Bundle.main.bundleIdentifier ?? "?")
                KeyValueRow(key: "App ID", value: liveAppID ?? "none")

                if liveGroups.isEmpty {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "xmark.octagon.fill")
                            .foregroundColor(T.bad)
                        Text("No app-group entitlement on this process.")
                            .font(T.body)
                            .foregroundColor(T.bad)
                    }
                    .padding(.vertical, 4)
                } else {
                    ForEach(liveGroups, id: \.self) { group in
                        KeyValueRow(key: "Group", value: group, tint: T.good)
                    }
                }

                Text("A profile in Documents cannot change this. The group has to be in the profile that signs the .app at install time — re-sign the IPA with a profile that carries it, then reinstall.")
                    .font(T.tiny)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func refreshLive() {
        liveGroups = LiveEntitlements.appGroups()
        liveAppID = LiveEntitlements.appIdentifier()
    }

    // MARK: Pairing / transport

    private var transportCard: some View {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        let pairingURL = docs?.appendingPathComponent("Pairing.plist")
        let hasPairing = pairingURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false
        let udid = PairingRecord.udid()
        let utun = DeviceConsole.interfaceAddresses().first { $0.name.hasPrefix("utun") }

        return Card {
            VStack(alignment: .leading, spacing: 6) {
                SectionLabel(text: "Pairing / transport")
                KeyValueRow(key: "Pairing", value: hasPairing ? "Documents/Pairing.plist" : "not imported")
                KeyValueRow(key: "UDID", value: udid ?? "—")
                KeyValueRow(key: "utun",
                            value: utun.map { "\($0.name) \($0.address)" } ?? "none — LocalDevVPN off",
                            tint: utun == nil ? T.warn : T.good)
                Text("The LIVE DEVICE CONSOLE and a future debug/install transport use this pairing record. It has no effect on app groups or the kernel.")
                    .font(T.tiny)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: Import

    private var importCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionLabel(text: "Import credentials")
                HStack(spacing: 10) {
                    Button {
                        importing = true
                    } label: {
                        Label("Import files", systemImage: "square.and.arrow.down")
                            .font(.system(size: 15, weight: .semibold))
                            .frame(maxWidth: .infinity, minHeight: 40)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(T.accent)

                    Button {
                        browser.chdir(store.directory.path)
                        store.note("Files tab now points at Documents/Credentials.")
                    } label: {
                        Label("Browse", systemImage: "folder")
                            .font(.system(size: 15, weight: .semibold))
                            .frame(maxWidth: .infinity, minHeight: 40)
                    }
                    .buttonStyle(.bordered)
                }

                Text("Accepts .p12 / .pfx, .mobileprovision and .ipa. Files are copied into Documents/Credentials, which the Files tab can browse. The .p12 password is stored in this app's Keychain item, never in Documents.")
                    .font(T.tiny)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if !store.status.isEmpty {
                    Text(store.status)
                        .font(T.monoSm)
                        .foregroundColor(store.status.hasPrefix("✓") ? T.good : T.warn)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let error = store.lastError, !error.isEmpty {
                    Text(error)
                        .font(T.monoSm)
                        .foregroundColor(T.bad)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: Identities

    private var identityCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 4) {
                SectionLabel(text: "Identities (.p12)")
                if store.identities.isEmpty {
                    Text("None yet. Import a .p12 exported from Keychain (private key included).")
                        .font(T.body)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.vertical, 4)
                } else {
                    ForEach(store.identities) { identity in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: store.selectedIdentityID == identity.fileName
                                  ? "largecircle.fill.circle" : "circle")
                                .font(.system(size: 15))
                                .foregroundColor(store.selectedIdentityID == identity.fileName ? T.accent : .secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(identity.displayName)
                                    .font(T.body)
                                    .foregroundColor(.primary)
                                    .lineLimit(1)
                                Text("\(identity.teamID.isEmpty ? "team ?" : identity.teamID) · \(identity.expiryText)"
                                     + (identity.passwordStored ? " · password saved" : ""))
                                    .font(T.monoSm)
                                    .foregroundColor(identity.expired ? T.bad : .secondary)
                            }
                            Spacer(minLength: 6)
                            if !identity.unlocked {
                                Button("Unlock") { unlockTarget = identity }
                                    .font(.system(size: 12, weight: .semibold))
                                    .buttonStyle(.borderless)
                            }
                        }
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                        .onTapGesture { store.selectedIdentityID = identity.fileName }
                        .contextMenu {
                            Button(role: .destructive) {
                                store.delete(fileName: identity.fileName)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                        if identity.fileName != store.identities.last?.fileName {
                            Divider()
                        }
                    }
                }
            }
        }
    }

    // MARK: Profiles

    private var profileCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 4) {
                SectionLabel(text: "Provisioning profiles")
                if store.profiles.isEmpty {
                    Text("None yet. Import a .mobileprovision for this bundle ID.")
                        .font(T.body)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.vertical, 4)
                } else {
                    ForEach(store.profiles) { profile in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: store.selectedProfileID == profile.fileName
                                      ? "largecircle.fill.circle" : "circle")
                                    .font(.system(size: 15))
                                    .foregroundColor(store.selectedProfileID == profile.fileName ? T.accent : .secondary)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(profile.name)
                                        .font(T.body)
                                        .lineLimit(1)
                                    Text("\(profile.teamID.isEmpty ? "team ?" : profile.teamID) · \(profile.expiryText) · \(profile.deviceCount) device(s)")
                                        .font(T.monoSm)
                                        .foregroundColor(profile.expired ? T.bad : .secondary)
                                }
                                Spacer(minLength: 6)
                                if profile.hasLum1naGroup {
                                    Pill(text: "group", color: T.good)
                                }
                                if profile.expired {
                                    Pill(text: "expired", color: T.bad)
                                }
                            }
                            Text(profile.appID.isEmpty ? "no application-identifier" : profile.appID)
                                .font(T.monoSm)
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                            if !profile.appGroups.isEmpty {
                                Text("groups: " + profile.appGroups.joined(separator: ", "))
                                    .font(T.monoSm)
                                    .foregroundColor(profile.hasLum1naGroup ? T.good : .secondary)
                                    .lineLimit(2)
                            }
                        }
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                        .onTapGesture { store.selectedProfileID = profile.fileName }
                        .contextMenu {
                            Button(role: .destructive) {
                                store.delete(fileName: profile.fileName)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                        if profile.fileName != store.profiles.last?.fileName {
                            Divider()
                        }
                    }
                }
            }
        }
    }

    // MARK: Checks

    private var checkCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 9) {
                SectionLabel(text: "Pair check")
                ForEach(store.checks()) { check in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: check.ok ? "checkmark.circle.fill" : "xmark.circle")
                            .font(.system(size: 14))
                            .foregroundColor(check.ok ? T.good : T.bad)
                            .padding(.top, 1)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(check.title)
                                .font(T.body)
                            Text(check.detail)
                                .font(T.monoSm)
                                .foregroundColor(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Text("All green except the last row means the credential pair is usable to sign/install another IPA. It still does not grant this process the group.")
                    .font(T.tiny)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
            }
        }
    }

    // MARK: Handoff

    private var handoffCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 9) {
                SectionLabel(text: "Handoff")
                Button {
                    UIPasteboard.general.string = store.handoff()
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy handoff block",
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 15, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.bordered)
                Text("Paste this into the GitHub signed-IPA run or a terminal signer. It lists the exact certificate, profile, app ID, groups and expiry that were validated here.")
                    .font(T.tiny)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: Unlock sheet

    private func unlockSheet(_ target: SigningIdentity) -> some View {
        NavigationStack {
            Form {
                Section("Encrypted identity") {
                    Text(target.fileName).font(T.monoSm)
                    SecureField(".p12 password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Toggle("Remember in Keychain", isOn: $remember)
                }
                Section {
                    Text("The password goes into this app's Keychain item and is used only when a signer needs the identity. It never touches Documents.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Unlock .p12")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        unlockTarget = nil
                        password = ""
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Unlock") {
                        _ = store.unlock(fileName: target.fileName,
                                         password: password,
                                         remember: remember)
                        unlockTarget = nil
                        password = ""
                        refreshLive()
                    }
                }
            }
        }
    }
}
