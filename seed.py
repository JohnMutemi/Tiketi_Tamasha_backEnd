#!/usr/bin/env python3
from faker import Faker
from app import app
from datetime import datetime
from models import db, User, Event, Ticket, Payment, Category, EventCategory
import random

fake = Faker()

# Define conversion rate from USD to KSh (example rate: 1 USD = 145 KSh)
USD_TO_KSH_CONVERSION_RATE = 145

# Define price ranges for different ticket types in USD
TICKET_PRICE_RANGES = {
    'Early Booking': (10.0, 30.0),  # $10 to $30
    'Regular': (30.0, 60.0),        # $30 to $60
    'VIP': (60.0, 100.0)            # $60 to $100
}

# Define image URLs and descriptions related to event types
EVENT_INFO = {
    'After Work Party': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761652/hcszbtggl8emdtkv5oqp.png',
        'description': 'Join us for a fun evening with drinks and music to unwind after a busy work week!'
    },
    'Feel The Beat Concert': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761653/dvmlwz2pjdzicszotqno.png',
        'description': 'Experience an electrifying night of live music and dance with top artists!'
    },
    'Webinar': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761654/bwszj0ew9ppc8g2mv9eo.png',
        'description': 'Participate in an insightful online seminar with industry experts on the latest trends!'
    },
    'Tech Talk': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761655/gca2ow8paiie3bswvtbv.png',
        'description': 'Get the latest updates and insights from technology leaders and innovators!'
    },
    'Art Exhibition': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761658/t4gyxrq6vxvpdmo1syfc.png',
        'description': 'Explore a curated collection of artworks from emerging and established artists!'
    },
    'Music Festival': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761657/r0eqyxnmcee2x0sso3bb.png',
        'description': 'Enjoy a multi-day festival featuring a diverse lineup of music acts across multiple stages!'
    },
    'Jazz Concert': {
        'image_url': 'https://res.cloudinary.com/dhxtzhs6h/image/upload/v1722761664/nqkzmeez6pcv07mzdryh.png',
        'description': 'Immerse yourself in a night of smooth jazz with performances by renowned musicians!'
    }
}

EVENT_TYPES = list(EVENT_INFO.keys())

def generate_ticket_price(ticket_type):
    """Generate ticket price in KSh based on the ticket type."""
    min_price, max_price = TICKET_PRICE_RANGES[ticket_type]
    price_usd = random.uniform(min_price, max_price)
    price_ksh = price_usd * USD_TO_KSH_CONVERSION_RATE
    return round(price_ksh, 2)

def seed_data():
    with app.app_context():
        # Drop existing tables and create new ones
        db.drop_all()
        db.create_all()

        # Clear session
        db.session.remove()

        # Create Users with plaintext passwords (only for testing, not for production)
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('adminpass')

        organizer1 = User(username='janedoe', email='janedoe@example.com', role='event_organizer')
        organizer1.set_password('securepass')

        organizer2 = User(username='michaelsmith', email='michaelsmith@example.com', role='event_organizer')
        organizer2.set_password('michaelpass')

        customer1 = User(username='emilybrown', email='emilybrown@example.com', role='customer')
        customer1.set_password('emilypass')

        customer2 = User(username='davidjohnson', email='davidjohnson@example.com', role='customer')
        customer2.set_password('davidpass')

        customer3 = User(username='sarahjones', email='sarahjones@example.com', role='customer')
        customer3.set_password('sarahpass')

        customer4 = User(username='lindaallen', email='lindaallen@example.com', role='customer')
        customer4.set_password('lindapass')

        db.session.add(admin)
        db.session.add(organizer1)
        db.session.add(organizer2)
        db.session.add(customer1)
        db.session.add(customer2)
        db.session.add(customer3)
        db.session.add(customer4)

        # Create Categories
        categories = ['Music', 'Technology', 'Arts', 'Sports', 'Food']
        for category_name in categories:
            category = Category(name=category_name)
            db.session.add(category)

        # Commit the users and categories
        db.session.commit()

        # Create Events using Faker with updated descriptions
        organizers = [organizer1, organizer2]
        events = []  # List to keep track of created events

        for _ in range(10):  # Creating 10 events
            event_type = random.choice(EVENT_TYPES)
            event_info = EVENT_INFO[event_type]
            event = Event(
                title=event_type,
                description=event_info['description'],
                location=fake.city(),
                start_time=fake.date_time_between(start_date='now', end_date='+1y'),
                end_time=fake.date_time_between(start_date='+1y', end_date='+2y'),
                organizer_id=random.choice(organizers).id,
                total_tickets=random.randint(50, 500),
                remaining_tickets=random.randint(0, 500),
                image_url=event_info['image_url']
            )
            db.session.add(event)
            events.append(event)  # Keep track of created events

        # Commit the events
        db.session.commit()

        # Create Event Categories
        event_ids = [event.id for event in events]  
        category_ids = [category.id for category in Category.query.all()]

        added_event_categories = set()  # To track added event-category pairs

        for event_id in event_ids:
            # Assign 1 to 3 random categories to each event
            for _ in range(random.randint(1, 3)):
                category_id = random.choice(category_ids)
                if (event_id, category_id) not in added_event_categories:
                    event_category = EventCategory(
                        event_id=event_id,
                        category_id=category_id
                    )
                    db.session.add(event_category)
                    added_event_categories.add((event_id, category_id))

        # Commit the event categories
        db.session.commit()

        # Create Tickets for Each Event
        tickets = []
        for event in events:
            # Ensure each event gets at least one ticket
            for ticket_type in ['Early Booking', 'Regular', 'VIP']:
                ticket = Ticket(
                    event_id=event.id,
                    user_id=random.choice([customer1.id, customer2.id, customer3.id, customer4.id]),
                    ticket_type=ticket_type,
                    price=generate_ticket_price(ticket_type),
                    quantity=random.randint(1, 3),
                    status='pending'
                )
                db.session.add(ticket)
                tickets.append(ticket)  # Keep track of created tickets

        # Commit the tickets
        db.session.commit()

        # Create Payments for a subset of tickets
        num_payments = 5  
        tickets_to_pay = random.sample(tickets, num_payments)
        for ticket in tickets_to_pay:
            payment = Payment(
                ticket_id=ticket.id,
                amount=ticket.price * ticket.quantity,
                payment_method=random.choice(['MPESA STK', 'Credit Card']),
                payment_status='completed'
            )
            db.session.add(payment)

        # Commit all changes to the database
        db.session.commit()

if __name__ == '__main__':
    seed_data()
    print("Database seeded!")
