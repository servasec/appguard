package controllers

import (
	"errors"
	"testing"

	"github.com/servasec/appguard/backend/config"
	"github.com/servasec/appguard/backend/models"
	"github.com/servasec/appguard/backend/testutil"
	"gorm.io/gorm"
)

func TestWebhookDeliveryIsRetriedWhenProcessingFails(t *testing.T) {
	db := testutil.SetupTestDB()
	const delivery = "atomic-retry-test"
	if err := db.Where("provider = ? AND delivery_id = ?", "github", delivery).Delete(&models.RepositoryWebhookDelivery{}).Error; err != nil {
		t.Fatal(err)
	}

	created, err := processWebhookDelivery("github", delivery, "push", func(*gorm.DB) error {
		return errors.New("temporary status update failure")
	})
	if err == nil || created {
		t.Fatalf("failed processing must roll back the delivery marker, created=%v err=%v", created, err)
	}

	var count int64
	if err := config.DB.Model(&models.RepositoryWebhookDelivery{}).Where("provider = ? AND delivery_id = ?", "github", delivery).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed processing left %d delivery markers", count)
	}

	created, err = processWebhookDelivery("github", delivery, "push", func(*gorm.DB) error { return nil })
	if err != nil || !created {
		t.Fatalf("retry should process the previously failed delivery, created=%v err=%v", created, err)
	}

	called := false
	created, err = processWebhookDelivery("github", delivery, "push", func(*gorm.DB) error {
		called = true
		return nil
	})
	if called {
		t.Fatal("duplicate delivery must not be processed again")
	}
	if err != nil || created {
		t.Fatalf("successful delivery should be deduplicated, created=%v err=%v", created, err)
	}
}
