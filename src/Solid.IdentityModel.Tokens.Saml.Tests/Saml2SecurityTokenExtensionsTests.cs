﻿using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace Solid.IdentityModel.Tokens.Saml.Tests
{
    public class Saml2SecurityTokenExtensionsTests
    {
        [Theory]
        [InlineData("https://notused")]
        [InlineData("https://otherurl")]
        public void ShouldAddSubjectConfirmationData(string recipient)
        {
            var assertion = new Saml2Assertion(new Saml2NameIdentifier("__notused__"));
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("__notused__"));

            var recipientUrl = new Uri(recipient);
            var token = new Saml2SecurityToken(assertion);
            token.SetRecipient(recipientUrl);

            var bearers = token.Assertion.Subject.SubjectConfirmations.Where(c => c.Method == Saml2Constants.ConfirmationMethods.Bearer);
            Assert.Single(bearers);
            var data = bearers.Single().SubjectConfirmationData;
            Assert.NotNull(data);
            Assert.Equal(recipientUrl, data.Recipient);
            Assert.Null(data.InResponseTo);
        }

        [Theory]
        [InlineData("https://notused")]
        [InlineData("https://otherurl")]
        public void ShouldAddToExistingSubjectConfirmationData(string recipient)
        {
            var assertion = new Saml2Assertion(new Saml2NameIdentifier("__notused__"));
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("__notused__"));
            assertion.Subject.SubjectConfirmations.Add(new Saml2SubjectConfirmation(Saml2Constants.ConfirmationMethods.Bearer));

            var recipientUrl = new Uri(recipient);
            var token = new Saml2SecurityToken(assertion);
            token.SetRecipient(recipientUrl);

            var bearers = token.Assertion.Subject.SubjectConfirmations.Where(c => c.Method == Saml2Constants.ConfirmationMethods.Bearer);
            Assert.Single(bearers);
            var data = bearers.Single().SubjectConfirmationData;
            Assert.NotNull(data);
            Assert.Equal(recipientUrl, data.Recipient);
            Assert.Null(data.InResponseTo);
        }

        [Fact]
        public void ShouldAddSubjectConfirmationDataWithInResponseTo()
        {
            var inResponseTo = $"_{Guid.NewGuid()}";
            var assertion = new Saml2Assertion(new Saml2NameIdentifier("__notused__"));
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("__notused__"));

            var recipientUrl = new Uri("https://notused");
            var token = new Saml2SecurityToken(assertion);
            token.SetRecipient(recipientUrl, inResponseTo);

            var bearers = token.Assertion.Subject.SubjectConfirmations.Where(c => c.Method == Saml2Constants.ConfirmationMethods.Bearer);
            Assert.Single(bearers);
            var data = bearers.Single().SubjectConfirmationData;
            Assert.NotNull(data);
            Assert.NotNull(data.InResponseTo);
            Assert.Equal(inResponseTo, data.InResponseTo.Value);
        }
    }
}
