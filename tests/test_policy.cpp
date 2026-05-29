#include <gtest/gtest.h>

#include <set>
#include <string>

#include "pwfilter/blacklist.hpp"
#include "pwfilter/breach.hpp"
#include "pwfilter/policy.hpp"

using namespace pwfilter;

namespace {

// Test double: reports a fixed set as breached and records whether it was consulted.
class FakeBreach : public IBreachChecker {
 public:
    mutable bool called = false;
    std::set<std::u16string> breached;

    bool IsBreached(std::u16string_view p) const override {
        called = true;
        return breached.count(std::u16string(p)) > 0;
    }
};

}  // namespace

TEST(Policy, AcceptsAStrongPassword) {
    Validator v(PolicyConfig{}, nullptr, nullptr);
    const auto r = v.Evaluate(u"Wm7!Kp4@Zb9#");
    EXPECT_TRUE(r.allowed);
    EXPECT_EQ(r.rule, RuleId::Ok);
}

TEST(Policy, RejectsByEachLocalRuleInOrder) {
    Validator v(PolicyConfig{}, nullptr, nullptr);

    EXPECT_EQ(v.Evaluate(u"Ab1!xy").rule, RuleId::TooShort);
    EXPECT_EQ(v.Evaluate(u"aaaabbbbccccdddd").rule, RuleId::NotEnoughClasses);
    EXPECT_EQ(v.Evaluate(u"Aaaaaa1!xkmp").rule, RuleId::RepeatRun);
    EXPECT_EQ(v.Evaluate(u"Habcd9!xkmp?").rule, RuleId::Sequence);
    EXPECT_EQ(v.Evaluate(u"Hqwer9!xmkp?").rule, RuleId::KeyboardPattern);
}

TEST(Policy, RejectsIdentityAndCompanyTerms) {
    PolicyConfig cfg;
    cfg.company_terms = {u"securitix"};
    Validator v(cfg, nullptr, nullptr);

    EXPECT_EQ(v.Evaluate(u"Mrossi#Xy9qK", u"mrossi", u"").rule, RuleId::ContainsAccountName);
    EXPECT_EQ(v.Evaluate(u"Rossi#Xy9qKL", u"", u"Mario Rossi").rule, RuleId::ContainsFullName);
    EXPECT_EQ(v.Evaluate(u"Securitix#9Xk").rule, RuleId::CompanyTerm);
}

TEST(Policy, RejectsBlacklisted) {
    Blacklist bl;
    bl.Add(u"P@ssw0rd2026");
    Validator v(PolicyConfig{}, &bl, nullptr);
    EXPECT_EQ(v.Evaluate(u"P@ssw0rd2026").rule, RuleId::Blacklisted);
}

TEST(Policy, RejectsBreachedWhenCheckerSaysSo) {
    FakeBreach fake;
    fake.breached.insert(u"CorrectHorse9!");
    Validator v(PolicyConfig{}, nullptr, &fake);

    const auto r = v.Evaluate(u"CorrectHorse9!");
    EXPECT_FALSE(r.allowed);
    EXPECT_EQ(r.rule, RuleId::Breached);
    EXPECT_TRUE(fake.called);
}

TEST(Policy, BreachCheckIsLast_NotConsultedWhenLocalRuleFails) {
    FakeBreach fake;
    fake.breached.insert(u"short");  // would match, but rule fails earlier
    Validator v(PolicyConfig{}, nullptr, &fake);

    const auto r = v.Evaluate(u"short");
    EXPECT_FALSE(r.allowed);
    EXPECT_EQ(r.rule, RuleId::TooShort);
    EXPECT_FALSE(fake.called);  // never reached the expensive check
}

TEST(Policy, BreachCheckDisabledByConfig) {
    FakeBreach fake;
    fake.breached.insert(u"Wm7!Kp4@Zb9#");
    PolicyConfig cfg;
    cfg.check_breach = false;
    Validator v(cfg, nullptr, &fake);

    const auto r = v.Evaluate(u"Wm7!Kp4@Zb9#");
    EXPECT_TRUE(r.allowed);
    EXPECT_FALSE(fake.called);
}

TEST(Policy, RuleNamesAreStable) {
    EXPECT_STREQ(RuleName(RuleId::Breached), "Breached");
    EXPECT_STREQ(RuleName(RuleId::Ok), "Ok");
    EXPECT_STREQ(RuleName(RuleId::ContainsAccountName), "ContainsAccountName");
}
